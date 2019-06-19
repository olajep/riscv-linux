/*
 * OWL Trace device driver
 *
 * Copyright (C) 2018 Clemson University
 * Written by Ola Jeppsson <ola.jeppsson@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called COPYING.
 */

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/gpio/driver.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/preempt.h>
#include <linux/mmap_notifier.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#ifdef __riscv
/* HACK: See get_timestamp() */
#include <asm/csr.h>
#endif
#include <uapi/linux/owl.h>

#include <linux/uaccess.h>

#define DRV_NAME "riscv-tracectrl"

/* Register offsets */
#define TRACECTRL_CONFIG	0x000 /* config register */
#define TRACECTRL_BUF_MASK	0x008 /* mask size of trace buffer 0 */
#define TRACECTRL_STATUS_BASE	0x100 /* buffer status base */
#define TRACECTRL_BUF_BASE	0x500 /* base address of trace buffers */

/* Register bits */
#define CONFIG_ENABLE				1
#define CONFIG_IRQEN				2
#define CONFIG_IGNORE_ILLEGAL_INSN		4

#define MAX_DEVICES 1 /* TODO: (num_possible_cpus()) */

static dev_t tracectrl_devt;
static struct class tracectrl_class;
static DEFINE_IDA(tracectrl_ida);

struct tracectrl_dma_buf {
	void *buf;
	dma_addr_t handle;
	unsigned int cpu;
};

struct tracectrl {
	bool enabled;
	void __iomem *base_addr;
	spinlock_t lock;

	struct cdev cdev;
	int minor;
	struct device dev;

	size_t dma_size;
	struct dma_pool *dma_pool;
	struct tracectrl_dma_buf dma_bufs[1024];
	size_t used_dma_bufs;

	/* TODO: Optimize this. In many cases we the scheduler will do task A
	 * --> kthread-> task A. So if we keep track of the previously
	 * scheduled user task (by pid?), we don't need to insert
	 * duplicates. */
	struct owl_sched_info sched_info[1024];
	size_t used_sched_info_entries;

	struct owl_map_info maps[1024];
	size_t used_map_entries;

	enum owl_trace_format trace_format;

	struct preempt_notifier preempt_notifier;
	struct mmap_notifier mmap_notifier;

	/* Not implemented */
	pid_t filter_dsid;

	u32 clock_divider;
	bool ignore_illegal_insn;
};

static inline void tracectrl_reg_writel(u32 value, struct tracectrl *ctrl,
				     unsigned long offset)
{
	writel(value, (u8 __iomem *) ctrl->base_addr + offset);
}

static inline void tracectrl_reg_writeq(u64 value, struct tracectrl *ctrl,
				     unsigned long offset)
{
#ifdef writeq
	writeq(value, (u8 __iomem *) ctrl->base_addr + offset);
#else
	writel((u32) ((value >>  0) & 0xffffffff),
	       (u8 __iomem *) ctrl->base_addr + offset);
	writel((u32) ((value >> 32) & 0xffffffff),
	       (u8 __iomem *) ctrl->base_addr + offset + 4);
#endif
}


static inline u32 tracectrl_reg_readl(struct tracectrl *ctrl, unsigned long offset)
{
	return readl((u8 __iomem *) ctrl->base_addr + offset);
}

static inline u64 tracectrl_reg_readq(struct tracectrl *ctrl, unsigned long offset)
{
#ifdef readq
	return readq((u8 __iomem *) ctrl->base_addr + offset);
#else
	u32 tmp;
	u64 val;
	tmp = readl((u8 __iomem *) ctrl->base_addr + offset);
	val = readl((u8 __iomem *) ctrl->base_addr + offset + 4);
	val = (val << 32) | tmp;
	return val;
#endif
}

static const struct of_device_id tracectrl_of_match[] = {
	{ .compatible = "clemson,trace-ctrl" },
	{ }
};
MODULE_DEVICE_TABLE(of, tracectrl_of_match);

static ssize_t config_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	u32 reg;
	struct tracectrl *ctrl = dev_get_drvdata(dev);

	reg = tracectrl_reg_readl(ctrl, TRACECTRL_CONFIG);

	return sprintf(buf, "%x\n", reg);
}
static DEVICE_ATTR_RO(config);

static ssize_t status_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	u32 reg;
	struct tracectrl *ctrl = dev_get_drvdata(dev);

	reg = tracectrl_reg_readl(ctrl, TRACECTRL_STATUS_BASE);

	return sprintf(buf, "%x\n", reg);
}
static DEVICE_ATTR_RO(status);

static ssize_t dump_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	ssize_t n;
	struct tracectrl *ctrl = dev_get_drvdata(dev);

	if (!ctrl->used_dma_bufs)
		return 0;

	dma_sync_single_for_cpu(dev, ctrl->dma_bufs[0].handle, ctrl->dma_size,
				DMA_FROM_DEVICE);
	n = min(ctrl->dma_size, PAGE_SIZE - 8);
	memcpy(buf, ctrl->dma_bufs[0].buf, n);

	return n;
}
static DEVICE_ATTR_RO(dump);

static struct attribute *tracectrl_attrs[] = {
	&dev_attr_config.attr,
	&dev_attr_status.attr,
	&dev_attr_dump.attr,
	NULL,
};

static const struct attribute_group tracectrl_attr_group = {
	.name = "tracectrl",
	.attrs = tracectrl_attrs,
};

union ioctl_arg {
	struct owl_status	status;
	struct owl_config	config;
	struct owl_trace_header	trace_header;
};

static int ioctl_get_status(struct tracectrl *ctrl, union ioctl_arg *arg)
{
	struct owl_status *status = &arg->status;

	/* lock */
	status->enabled = ctrl->enabled;
	/* unlock */

	/* TODO: Rework */
	status->stream_info_size = nr_cpu_ids * sizeof(struct owl_stream_info);
	status->tracebuf_size = ctrl->dma_size * ctrl->used_dma_bufs;
	status->sched_info_size =
		ctrl->used_sched_info_entries * sizeof(struct owl_sched_info);
	status->map_info_size =
		ctrl->used_map_entries * sizeof(struct owl_map_info);

	return 0;
}

static int ioctl_set_config(struct tracectrl *ctrl, union ioctl_arg *arg)
{
	extern int pid_max;
	struct owl_config *config = &arg->config;

	switch (config->trace_format) {
	case OWL_TRACE_FORMAT_DEFAULT:
		break;
	default:
		return -EINVAL;
	}
	ctrl->trace_format = config->trace_format;

	/* TODO: Rework */
	if (config->dsid &&
	    (config->dsid < 1 || config->dsid >= pid_max)) {
		return -EINVAL;
	}
	ctrl->filter_dsid = config->dsid;

	ctrl->clock_divider = config->clock_divider ?: 1;

	ctrl->ignore_illegal_insn = config->ignore_illegal_insn;

	return 0;
}

/**
 * tracectrl_update_buf - Update buffer pointer in control regs
 * @ctrl:	tracectrl device
 * @pos:	buffer position
 * @addr:	buffer pointer
 * @clear_full:	clear the full flag
 *
 * NB: Lock should be held when calling this function
 *
 * Return: void
 */
static void tracectrl_update_buf(struct tracectrl *ctrl, unsigned long pos,
				 u64 addr, bool clear_full)
{
	unsigned long offs;

	/* TODO: Support more than 32 cpus */
	offs = TRACECTRL_BUF_BASE + 8 * pos;
	tracectrl_reg_writeq(addr, ctrl, offs);
	if (clear_full) {
		tracectrl_reg_writeq(BIT_ULL(pos), ctrl, TRACECTRL_STATUS_BASE);
		//tracectrl_reg_writel(BIT_UL(pos), ctrl, TRACECTRL_STATUS_BASE);
	}
}


static void tracectrl_free_all_dma_bufs(struct tracectrl *ctrl)
{
	struct tracectrl_dma_buf *buf;

	while (ctrl->used_dma_bufs) {
		ctrl->used_dma_bufs--;
		buf = &ctrl->dma_bufs[ctrl->used_dma_bufs];
		dma_pool_free(ctrl->dma_pool, buf->buf, buf->handle);
	}
}

/* Need to rework since we can't do any locking in interrupt handler */
static struct tracectrl_dma_buf *
tracectrl_dma_buf_alloc(struct tracectrl *ctrl, unsigned long cpu,
			gfp_t gfp_flags)
{
	struct tracectrl_dma_buf *buf;

	if (ctrl->used_dma_bufs >= ARRAY_SIZE(ctrl->dma_bufs))
		return NULL;

	buf = &ctrl->dma_bufs[ctrl->used_dma_bufs];
	buf->cpu = (unsigned int) cpu;

	/* TODO: Revisit when H/W gets buffer pointer. Then there's no need
	 * to use zero allocated buffers. */
	buf->buf = dma_pool_zalloc(ctrl->dma_pool, gfp_flags, &buf->handle);

	if (buf->buf)
		ctrl->used_dma_bufs++;

	return buf;
}

void tracectrl_init_map_info(struct tracectrl *ctrl);

/* Redo locking?!? */
static int ioctl_enable(struct tracectrl *ctrl,
			union ioctl_arg __always_unused *arg)
{
	u32 val;

	struct tracectrl_dma_buf *buf0, *buf1;

	/* lock */
	if (ctrl->enabled) {
		/* unlock */
		return 0; /* Idempotent. Or is -EBUSY better? */
	}

	/* unlock */

	tracectrl_free_all_dma_bufs(ctrl);

	/* TODO: for each cpu do ... { */
	buf0 = tracectrl_dma_buf_alloc(ctrl, 0, GFP_KERNEL);
	buf1 = tracectrl_dma_buf_alloc(ctrl, 0, GFP_KERNEL);
	if (!buf0 || !buf1) {
		tracectrl_free_all_dma_bufs(ctrl);
		return -ENOMEM;
	}

	tracectrl_update_buf(ctrl, 0, buf0->handle, true);
	tracectrl_update_buf(ctrl, 1, buf1->handle, true);
	/* TODO: for each cpu do ... } */

	tracectrl_init_map_info(ctrl);
	ctrl->used_sched_info_entries = 0;
	preempt_notifier_inc();
	preempt_notifier_all_register(&ctrl->preempt_notifier);

	/* Memory barrier here */

	ctrl->enabled = true;

	/* Memory barrier here */

	val = tracectrl_reg_readl(ctrl, TRACECTRL_CONFIG);
	val |= CONFIG_ENABLE | CONFIG_IRQEN;
	if (ctrl->ignore_illegal_insn)
		val |= CONFIG_IGNORE_ILLEGAL_INSN;
	else
		val &= ~CONFIG_IGNORE_ILLEGAL_INSN;
	tracectrl_reg_writel(val, ctrl, TRACECTRL_CONFIG);
	/* unlock */

	return 0;
}

static int ioctl_disable(struct tracectrl *ctrl,
			 union ioctl_arg __always_unused *arg)
{
	u32 val;

	if (!ctrl->enabled)
		return 0;

	/* lock */
	val = tracectrl_reg_readl(ctrl, TRACECTRL_CONFIG);
	val &= ~(CONFIG_ENABLE | CONFIG_IRQEN);
	tracectrl_reg_writel(val, ctrl, TRACECTRL_CONFIG);
	while (val & CONFIG_ENABLE)
		val = tracectrl_reg_readl(ctrl, TRACECTRL_CONFIG);
	/* unlock */

	smp_mb();

	mmap_notifier_unregister(&ctrl->mmap_notifier);
	mmap_notifier_dec();
	preempt_notifier_unregister(&ctrl->preempt_notifier);
	preempt_notifier_dec();
	synchronize_rcu();

	smp_mb();

	/* lock */
	ctrl->enabled = false;
	/* unlock */

	return 0;
}

static size_t cpu_trace_stream_size(struct tracectrl *ctrl, unsigned int cpu)
{
	size_t i, n = 0;
	for (i = 0; i < ctrl->used_dma_bufs; i++) {
		if (ctrl->dma_bufs[i].cpu == cpu)
			n++;
	}
	return n * ctrl->dma_size;
}

static int ioctl_dump_trace(struct tracectrl *ctrl, union ioctl_arg *arg)
{
	size_t i, remaining, n;
	struct owl_trace_header *header = &arg->trace_header;
	u8 __user *p;
	unsigned int cpu;
	struct owl_stream_info si = { 0 };

	/* lock */
	if (ctrl->enabled) {
		/* unlock */
		return -EBUSY;
	}
	/* unlock */

	/* Initialize header kernel side values */
	header->trace_format = ctrl->trace_format;
	header->tracebuf_size		= 0;
	header->sched_info_size		= 0;
	header->map_info_size		= 0;
	header->stream_info_size	= 0;

	if (!ctrl->used_dma_bufs)
		return 0;

	/* Write cpu trace stream info */
	p = header->streaminfobuf;
	n = 0;
	remaining = header->max_stream_info_size;
	for_each_possible_cpu(cpu) {
		if (!remaining)
			break;
		n = min(remaining, sizeof(si));
		si.cpu = (u16)cpu;
		si.offs += si.size;
		si.size = cpu_trace_stream_size(ctrl, cpu);
		if (copy_to_user(p, &si, n))
			return -EFAULT;
		header->stream_info_size += n;
		p += n;
		remaining -= n;
	}

	/* Copy trace buffer */
	p = header->tracebuf;
	remaining = header->max_tracebuf_size;
	for_each_possible_cpu(cpu) {
		for (i = 0; i < ctrl->used_dma_bufs && remaining; i++) {
			if (ctrl->dma_bufs[i].cpu != cpu)
				continue;
			n = min(remaining, ctrl->dma_size);
			dma_sync_single_for_cpu(&ctrl->dev,
						ctrl->dma_bufs[i].handle,
						n,
						DMA_FROM_DEVICE);
			if (copy_to_user(p, ctrl->dma_bufs[i].buf, n))
				return -EFAULT;
			header->tracebuf_size += n;
			p += n;
			remaining -= n;
		}
	}

	/* Copy scheduling info */
	n = min_t(u64, header->max_sched_info_size,
		  ctrl->used_sched_info_entries *
			sizeof(struct owl_sched_info));
	if (copy_to_user(header->schedinfobuf, ctrl->sched_info, n))
		return -EFAULT;
	header->sched_info_size = n;

	/* Copy mapping info */
	n = min_t(u64, header->max_map_info_size,
		  ctrl->used_map_entries * sizeof(struct owl_map_info));
	if (copy_to_user(header->mapinfobuf, ctrl->maps, n))
		return -EFAULT;
	header->map_info_size = n;

	return 0;
}


static int (* const ioctl_handlers[])(struct tracectrl *, union ioctl_arg *) = {
	[_IOC_NR(OWL_IOCTL_STATUS)]	= ioctl_get_status,
	[_IOC_NR(OWL_IOCTL_CONFIG)]	= ioctl_set_config,
	[_IOC_NR(OWL_IOCTL_ENABLE)]	= ioctl_enable,
	[_IOC_NR(OWL_IOCTL_DISABLE)]	= ioctl_disable,
	[_IOC_NR(OWL_IOCTL_DUMP)]	= ioctl_dump_trace,
};

static long tracectrl_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	union ioctl_arg buf = { 0 };
	int ret;
	struct tracectrl *ctrl = file->private_data;

	if (_IOC_TYPE(cmd) != OWL_IOCTL_BASE ||
	    _IOC_NR(cmd) >= ARRAY_SIZE(ioctl_handlers) ||
	    _IOC_SIZE(cmd) > sizeof(buf))
		return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_WRITE)
		if (copy_from_user(&buf, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;

	ret = ioctl_handlers[_IOC_NR(cmd)](ctrl, &buf);
	if (ret < 0)
		return ret;

	if (_IOC_DIR(cmd) & _IOC_READ)
		if (copy_to_user((void __user *)arg, &buf, _IOC_SIZE(cmd)))
			return -EFAULT;

	return ret;
}

static int tracectrl_open(struct inode *inode, struct file *file)
{
	struct tracectrl *ctrl;

	ctrl = container_of(inode->i_cdev, struct tracectrl, cdev);
	file->private_data = ctrl;

	return nonseekable_open(inode, file);
}

static const struct file_operations tracectrl_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tracectrl_ioctl,
	.open		= tracectrl_open,
};

/* HACK: We should use perf_event_read_value() for portability !?!? */
static u64 get_timestamp(void)
{
#ifdef __riscv /* && 64bit */
	/* We can't use rdtime since it is not implemented in RocketCore.
	 * Instead it is emulated in bbl. But that triggers an invalid
	 * instruction exception that would distort the trace. */
	return csr_read(cycle);
#else
	return 0;
#endif
}

static void tracectrl_sched_in(struct preempt_notifier *notifier, int cpu)
{
	/* kernel/sched/core.c:__fire_sched_in_preempt_notifiers() does not
	 * NULL check ops in struct preempt_ops. */
}

static void tracectrl_insert_sched_info(struct tracectrl *ctrl,
				      struct task_struct *task)
{
	struct owl_sched_info *entry;
	if (ctrl->used_sched_info_entries >= ARRAY_SIZE(ctrl->sched_info))
		return;

	entry			= &ctrl->sched_info[ctrl->used_sched_info_entries];
	entry->timestamp	= get_timestamp();
	entry->cpu		= (u16) smp_processor_id();
	entry->has_mm		= task->mm != NULL;
	entry->in_execve	= task->in_execve;
	entry->kthread		= !!(task->flags & PF_KTHREAD);
	entry->task.pid		= (int) task_pid_nr(task);
	entry->task.ppid	= (int) task_ppid_nr(task);
	memcpy(entry->task.comm, task->comm, TASK_COMM_LEN);

	ctrl->used_sched_info_entries++;
}

static void tracectrl_sched_out(struct preempt_notifier *notifier,
				struct task_struct *next)
{
	struct tracectrl *ctrl =
		container_of(notifier, struct tracectrl, preempt_notifier);

	if (!ctrl->enabled)
		dev_warn(&ctrl->dev, "%s: device not enabled\n", __func__);

	tracectrl_insert_sched_info(ctrl, current);

}

static __read_mostly struct preempt_ops tracectrl_preempt_ops;

static void tracectrl_insert_map(struct tracectrl *ctrl,
				 struct vm_area_struct *vma,
				 struct task_struct *task)
{
	struct owl_map_info *entry;
	const char *path;
	char static_buf[ARRAY_SIZE(entry->path)], *buf = NULL;
	size_t len;

	if (!(vma->vm_flags & VM_EXEC))
		return;

	if (!current) {
		printk(KERN_INFO "tracectrl_mmap_event: no current task\n");
		return;
	}

	if (ctrl->used_map_entries >= ARRAY_SIZE(ctrl->maps))
		return;

#if 0
	if (vma->vm_file) /* We'll save some space but is it worth it?!? */
		return;
#endif

	entry = &ctrl->maps[ctrl->used_map_entries];
	entry->pid	= task->pid;
	entry->vm_start	= (u64) vma->vm_start;
	entry->vm_end	= (u64) vma->vm_end;

	if (vma->vm_file) {
		path = file_path(vma->vm_file, static_buf,
				 ARRAY_SIZE(static_buf));
		if (!IS_ERR(path))
			goto got_path;

		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buf) {
			path = "//enomem";
			goto got_path;
		}
		path = file_path(vma->vm_file, buf, PATH_MAX);
		if (IS_ERR(path)) {
			path = "//toolong";
			goto got_path;
		} else {
			/* We want the end of the path so we at least get the
			 * filename */
			len = strlen(path);
			path = path + len - min(ARRAY_SIZE(entry->path), len);
		}
	} else {
		/* TODO: else "[heap]" "[stack]" ...
		 * See kernel/events/core:perf_event_mmap_event() */
		path = "//nofile";
		goto got_path;
	}
got_path:
	strlcpy(entry->path, path, ARRAY_SIZE(entry->path));
	if (buf)
		kfree(buf);

	ctrl->used_map_entries++;
	if (ctrl->used_map_entries == ARRAY_SIZE(ctrl->maps))
		printk(KERN_INFO "tracectrl: map info full\n");
}

void tracectrl_init_map_info(struct tracectrl *ctrl)
{
	struct task_struct *p;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	ctrl->used_map_entries = 0;

	read_lock(&tasklist_lock);
	for_each_process(p) {
		mm = p->mm;
		if (!mm || p->flags & PF_KTHREAD)
			continue;
		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma; vma = vma->vm_next)
			tracectrl_insert_map(ctrl, vma, p);
		up_read(&mm->mmap_sem);
	}
	read_unlock(&tasklist_lock);

	mmap_notifier_inc();
	mmap_notifier_register(&ctrl->mmap_notifier);
}


static void tracectrl_mmap_event(struct mmap_notifier *notifier,
				 struct vm_area_struct *vma)
{
	struct tracectrl *ctrl =
		container_of(notifier, struct tracectrl, mmap_notifier);

	tracectrl_insert_map(ctrl, vma, current);
}

static __read_mostly struct mmap_notifier_ops tracectrl_mmap_notifier_ops;

/* TODO: Redo / implement locking */
static irqreturn_t tracectrl_irq_handler(int irq, void *dev_id)
{
	struct tracectrl *ctrl = dev_id;
	u32 config;
	u64 status;
	unsigned long pos, cpu;
	bool handled = false;
	dma_addr_t addr = 0;
	struct tracectrl_dma_buf *buf;

	/* lock */
	status = tracectrl_reg_readq(ctrl, TRACECTRL_STATUS_BASE);
	while (status) {
		/* TODO: Iterate over all instead of just first 32 cpu (64/2) */
		pos = __ffs64(status);
		cpu = pos / 2;

		buf = tracectrl_dma_buf_alloc(ctrl, cpu, GFP_ATOMIC);
		if (!buf) {
			/* TODO return wake thread and handle alloc there if
			 * it failed here. */
			printk(KERN_ERR "tracectrl irq failed to alloc\n");
			config = tracectrl_reg_readl(ctrl, TRACECTRL_CONFIG);
			config &= ~CONFIG_IRQEN;
			tracectrl_reg_writel(config, ctrl, TRACECTRL_CONFIG);
		} else {
			tracectrl_update_buf(ctrl, pos, buf->handle, true);
			addr = buf->handle;
		}
		handled = true;
		status &= ~BIT_ULL(pos);
	}
	/* unlock */

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

/**
 * tracectrl_probe - Platform probe for a tracectrl device
 * @pdev:	platform device
 *
 * Note: All interrupts are cleared + masked after function exits.
 *
 * Return: 0 on success, negative error otherwise.
 */
static int tracectrl_probe(struct platform_device *pdev)
{
	struct tracectrl *ctrl;
	struct resource *resource;
	int res = 0, irq;
	dev_t devt;

	ctrl = devm_kzalloc(&pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	platform_set_drvdata(pdev, ctrl);

	resource = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ctrl->base_addr = devm_ioremap_resource(&pdev->dev, resource);
	if (IS_ERR(ctrl->base_addr))
		return PTR_ERR(ctrl->base_addr);

	/* Interrupt */
	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "Could not get IRQ from platform data\n");
		return irq;
	}

	res = devm_request_irq(&pdev->dev, irq, tracectrl_irq_handler, 0,
			dev_name(&pdev->dev), ctrl);
	if (res) {
		dev_err(&pdev->dev, "Could not request IRQ\n");
		return res;
	}

	spin_lock_init(&ctrl->lock);

	res = sysfs_create_group(&pdev->dev.kobj, &tracectrl_attr_group);
	if (res < 0) {
		dev_err(&pdev->dev,
			"Can't register sysfs attr group: %d\n", res);
		return res;
	}

	/* This creates the minor number for the RPMB char device */
	res = ida_simple_get(&tracectrl_ida, 0, MAX_DEVICES, GFP_KERNEL);
	if (res < 0) {
		dev_err(&pdev->dev,
			"Can't register sysfs attr group: %d\n", res);
		goto out_sysfs_remove;
	}

	ctrl->minor = res;
	devt = MKDEV(MAJOR(tracectrl_devt), ctrl->minor);
	cdev_init(&ctrl->cdev, &tracectrl_fops);
	ctrl->cdev.owner = THIS_MODULE;

	res = cdev_add(&ctrl->cdev, devt, 1);
	if (res) {
		dev_err(&ctrl->dev,
			"char device registration failed\n");
		goto out_minor_remove;
	}
	ctrl->dev.class = &tracectrl_class;
	ctrl->dev.parent = pdev->dev.parent; /* no??? */
	ctrl->dev.devt = devt;
	ctrl->dev.groups = NULL;
	ctrl->dev.release = NULL;
	ctrl->dev.coherent_dma_mask = DMA_BIT_MASK(64);
	dev_set_name(&ctrl->dev, "tracectrl%d", ctrl->minor);
	ctrl->dev.devt = devt;
	res = device_register(&ctrl->dev);
	if (res)
		goto out_minor_remove;

	ctrl->dma_size = SZ_64K;
	ctrl->dma_pool = dma_pool_create(dev_name(&ctrl->dev), &ctrl->dev,
					 ctrl->dma_size, ctrl->dma_size, 0);
	if (!ctrl->dma_pool)
		goto out_device_destroy;

	/* Initialize registers */
	tracectrl_reg_writel(0, ctrl, TRACECTRL_CONFIG);
	tracectrl_reg_writel(ctrl->dma_size - 1, ctrl, TRACECTRL_BUF_MASK);

	tracectrl_preempt_ops.sched_in = tracectrl_sched_in;
	tracectrl_preempt_ops.sched_out = tracectrl_sched_out;
	preempt_notifier_init(&ctrl->preempt_notifier, &tracectrl_preempt_ops);
	tracectrl_mmap_notifier_ops.mmap = tracectrl_mmap_event;
	mmap_notifier_init(&ctrl->mmap_notifier, &tracectrl_mmap_notifier_ops);

	return 0;

out_device_destroy:
	device_destroy(&tracectrl_class, devt);
out_minor_remove:
	ida_simple_remove(&tracectrl_ida, ctrl->minor);
out_sysfs_remove:
	sysfs_remove_group(&pdev->dev.kobj, &tracectrl_attr_group);
	return res;
}

/**
 * tracectrl_remove - Driver removal function
 * @pdev:	platform device
 *
 * Return: 0 always
 */
static int tracectrl_remove(struct platform_device *pdev)
{
	struct tracectrl *ctrl = platform_get_drvdata(pdev);

	sysfs_remove_group(&pdev->dev.kobj, &tracectrl_attr_group);

	/* Disable tracing */
	tracectrl_reg_writel(0, ctrl, TRACECTRL_CONFIG);

	tracectrl_free_all_dma_bufs(ctrl);
	dma_pool_destroy(ctrl->dma_pool);

	return 0;
}

static struct platform_driver tracectrl_driver = {
	.driver	= {
		.name = DRV_NAME,
		.of_match_table = tracectrl_of_match,
	},
	.probe = tracectrl_probe,
	.remove = tracectrl_remove,
};

static void tracectrl_device_release(struct device *dev)
{
	/* No-op since we use devm_* */
}

static char *tracectrl_devnode(struct device *dev, umode_t *mode)
{
	//return kasprintf(GFP_KERNEL, "tracectrl/%s", dev_name(dev));
	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
	//return dev_name(dev);
}

static int __init tracectrl_module_init(void)
{
	int res;

	tracectrl_class.name = "tracectrl";
	tracectrl_class.owner = THIS_MODULE;
	tracectrl_class.devnode = tracectrl_devnode;
	tracectrl_class.dev_release = tracectrl_device_release;

	res = class_register(&tracectrl_class);
	if (res) {
		pr_err("Unable to register tracectrl class\n");
		return res;
	}

	res = alloc_chrdev_region(&tracectrl_devt, 0, MAX_DEVICES,
				  "tracectrl");
	if (res < 0) {
		pr_err("Failed to allocate tracectrl chrdev region %d\n", res);
		goto out_class_unregister;
	}
	return 0;
out_class_unregister:
	class_unregister(&tracectrl_class);
	return res;
}

static void __exit tracectrl_module_exit(void)
{
	class_unregister(&tracectrl_class);
	unregister_chrdev_region(tracectrl_devt, MAX_DEVICES);
}

module_platform_driver(tracectrl_driver);
module_init(tracectrl_module_init);
module_exit(tracectrl_module_exit);

MODULE_AUTHOR("Ola Jeppsson <ola.jeppsson@gmail.com>");
MODULE_DESCRIPTION("OWL TraceCtrl driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
