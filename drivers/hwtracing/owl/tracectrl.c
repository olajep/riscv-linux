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
#include <linux/idr.h>
#include <linux/cdev.h>
#include <uapi/linux/owl.h>

#include <linux/uaccess.h>

#define DRV_NAME "riscv-tracectrl"

/* Register offsets */
#define TRACECTRL_CONFIG	0x00 /* config register */
#define TRACECTRL_STATUS	0x04 /* status register */
#define TRACECTRL_BUF0_ADDR	0x10 /* base address of trace buffer 0 */
#define TRACECTRL_BUF0_MASK	0x18 /* mask size of trace buffer 0 */
#define TRACECTRL_BUF1_ADDR	0x20 /* base address of trace buffer 1 */
#define TRACECTRL_BUF1_MASK	0x28 /* mask size of trace buffer 1 */

/* Register bits */
#define CONFIG_ENABLE		1
#define CONFIG_IRQEN		2
#define STATUS_BUF0_FULL	1
#define STATUS_BUF1_FULL	2

#define MAX_DEVICES 1 /* TODO: (num_possible_cpus()) */

static dev_t tracectrl_devt;
static struct class tracectrl_class;
static DEFINE_IDA(tracectrl_ida);

struct tracectrl {
	void __iomem *base_addr;
	spinlock_t lock;
	size_t dma_size;
	void *dma_buf0;
	dma_addr_t dma_handle0;
	void *dma_buf1;
	dma_addr_t dma_handle1;
	struct cdev cdev;
	int minor;
	struct device dev;

	enum owl_trace_format trace_format;
	enum owl_metadata_format metadata_format;

	/* Not implemented */
	pid_t filter_dsid;
	u32 clock_divider;
};

static inline void tracectrl_reg_write(u32 value, struct tracectrl *ctrl,
				     unsigned long offset)
{
	writel(value, (u8 __iomem *) ctrl->base_addr + offset);
}

static inline u32 tracectrl_reg_read(struct tracectrl *ctrl, unsigned long offset)
{
	return readl((u8 __iomem *) ctrl->base_addr + offset);
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

	reg = tracectrl_reg_read(ctrl, TRACECTRL_CONFIG);

	return sprintf(buf, "%x\n", reg);
}
static DEVICE_ATTR_RO(config);

static ssize_t status_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	u32 reg;
	struct tracectrl *ctrl = dev_get_drvdata(dev);

	reg = tracectrl_reg_read(ctrl, TRACECTRL_STATUS);

	return sprintf(buf, "%x\n", reg);
}
static DEVICE_ATTR_RO(status);

static ssize_t dump_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	ssize_t n;
	struct tracectrl *ctrl = dev_get_drvdata(dev);

	dma_sync_single_for_cpu(dev, ctrl->dma_handle0, ctrl->dma_size,
				DMA_FROM_DEVICE);
	n = min(ctrl->dma_size, PAGE_SIZE - 8);
	memcpy(buf, ctrl->dma_buf0, n);

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
	u32 val;
	struct owl_status *status = &arg->status;

	val = tracectrl_reg_read(ctrl, TRACECTRL_CONFIG);
	status->enabled = val & CONFIG_ENABLE;

	/* TODO: Rework */
	status->tracebuf_size = 2 * ctrl->dma_size;
	status->metadatabuf_size = 0;

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

	switch (config->metadata_format) {
	case OWL_METADATA_FORMAT_DEFAULT:
		break;
	default:
		return -EINVAL;
	}
	ctrl->metadata_format = config->metadata_format;

	/* TODO: Rework */
	if (config->dsid &&
	    (config->dsid < 1 || config->dsid >= pid_max)) {
		return -EINVAL;
	}
	ctrl->filter_dsid = config->dsid;

	ctrl->clock_divider = config->clock_divider ?: 1;

	return 0;
}

/**
 * tracectrl_update_buf - Update buffer pointer in control regs
 * @ctrl:	tracectrl device
 * @base:	base address for buffer in control regs
 * @addr:	buffer pointer
 * @mask:	buffer mask (buffer size - 1)
 * @clear_full:	clear the full flag
 *
 * NB: Lock should be held when calling this function
 *
 * Return: void
 */
static void tracectrl_update_buf(struct tracectrl *ctrl, unsigned long base,
				 u64 addr, u64 mask, bool clear_full)
{
	u32 flag;
	tracectrl_reg_write((u32) (addr >>  0) & 0xffffffff, ctrl, base);
	tracectrl_reg_write((u32) (addr >> 32) & 0xffffffff, ctrl, base + 4);
	tracectrl_reg_write(mask, ctrl, base + 8);
	tracectrl_reg_write(0, ctrl, base + 0xc);
	if (clear_full) {
		flag = (base == TRACECTRL_BUF0_ADDR) ?
			STATUS_BUF0_FULL : STATUS_BUF1_FULL,
		tracectrl_reg_write(flag, ctrl, TRACECTRL_STATUS);
	}
}

static int ioctl_enable(struct tracectrl *ctrl,
			union ioctl_arg __always_unused *arg)
{
	u32 val;

	/* lock */
	val = tracectrl_reg_read(ctrl, TRACECTRL_CONFIG);
	val |= CONFIG_ENABLE | CONFIG_IRQEN;
	tracectrl_reg_write(val, ctrl, TRACECTRL_CONFIG);
	/* unlock */

	return 0;
}

static int ioctl_disable(struct tracectrl *ctrl,
			 union ioctl_arg __always_unused *arg)
{
	u32 val;

	/* lock */
	val = tracectrl_reg_read(ctrl, TRACECTRL_CONFIG);
	val &= ~(CONFIG_ENABLE | CONFIG_IRQEN);
	tracectrl_reg_write(val, ctrl, TRACECTRL_CONFIG);
	/* unlock */

	return 0;
}

static int ioctl_dump_trace(struct tracectrl *ctrl, union ioctl_arg *arg)
{
	u32 reg;
	size_t tracebuf_size;
	struct owl_trace_header *header = &arg->trace_header;

	/* lock */
	reg = tracectrl_reg_read(ctrl, TRACECTRL_CONFIG);
	/* unlock */

	if (reg & 1) /* enabled */
		return -EBUSY;

	/* TODO: Rework */
	header->trace_format = ctrl->trace_format;
	header->metadata_format = ctrl->metadata_format;
	tracebuf_size = min(2 * ctrl->dma_size, (size_t)header->tracebuf_size);
	header->tracebuf_size = tracebuf_size;

	dma_sync_single_for_cpu(&ctrl->dev, ctrl->dma_handle0,
				min(ctrl->dma_size, (size_t)tracebuf_size),
				DMA_FROM_DEVICE);
	dma_sync_single_for_cpu(&ctrl->dev, ctrl->dma_handle1,
				min(ctrl->dma_size, (size_t)tracebuf_size),
				DMA_FROM_DEVICE);
	if (copy_to_user(header->tracebuf, ctrl->dma_buf0,
				min(ctrl->dma_size, (size_t)tracebuf_size)))
		return -EFAULT;

	if (tracebuf_size > ctrl->dma_size) {
		if (copy_to_user((u8 *) header->tracebuf + ctrl->dma_size,
				 ctrl->dma_buf1,
				 min(ctrl->dma_size,
				     (size_t)tracebuf_size - ctrl->dma_size)))
			return -EFAULT;
	}

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


static irqreturn_t tracectrl_irq_handler(int irq, void *dev_id)
{
	struct tracectrl *ctrl = dev_id;
	u32 status, clear = 0;
	unsigned long reg;

	/* The RISC-V PLIC does not support?!? edge triggered interrupts (at
	 * least not the devicetree binding since there are no flags) so work
	 * around it by disabling the interrupt for now. Guess we'll have to
	 * implement this in hardware eventually. Sigh. */

	/* lock */
	status = tracectrl_reg_read(ctrl, TRACECTRL_STATUS);
	/* unlock */

	if (status & STATUS_BUF0_FULL) {
		clear = STATUS_BUF0_FULL;
		reg = TRACECTRL_BUF0_ADDR;
	} else if (status & STATUS_BUF1_FULL) {
		clear = STATUS_BUF1_FULL;
		reg = TRACECTRL_BUF1_ADDR;
	}

	if (clear) {
		/* TODO: Allocate more DMA memory suitable for trace buffer
		 * here, and add it to a linked list. */

		/* lock */
		/* TODO: Swap the buffer pointer here */
		(void)reg;
		tracectrl_reg_write(clear, ctrl, TRACECTRL_STATUS);
		/* unlock */
	}

	printk(KERN_INFO "tracectrl interrupt %u\n", status);

	return IRQ_HANDLED;
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

	/* TODO: Allocate buffer on user request, i.e., not here ... */
	ctrl->dma_size = SZ_64K;
	/* TODO: Use dma_pool_create so we satisfy hw alignment requirement. */
	ctrl->dma_buf0 = dma_alloc_coherent(&ctrl->dev, ctrl->dma_size,
					    &ctrl->dma_handle0, GFP_KERNEL);
	if (!ctrl->dma_buf0) {
		res = -ENOMEM;
		goto out_device_destroy;
	}
	ctrl->dma_buf1 = dma_alloc_coherent(&ctrl->dev, ctrl->dma_size,
					    &ctrl->dma_handle1, GFP_KERNEL);
	if (!ctrl->dma_buf1) {
		res = -ENOMEM;
		goto out_free_dma_buf0;
	}

	/* TODO: 64 bit write ... */
	tracectrl_update_buf(ctrl, TRACECTRL_BUF0_ADDR, ctrl->dma_handle0,
			     ctrl->dma_size - 1, true);
	tracectrl_update_buf(ctrl, TRACECTRL_BUF1_ADDR, ctrl->dma_handle1,
			     ctrl->dma_size - 1, true);

	return 0;

out_free_dma_buf0:
	dma_free_coherent(&ctrl->dev, ctrl->dma_size, ctrl->dma_buf0,
			  ctrl->dma_handle0);
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
	tracectrl_reg_write(0, ctrl, TRACECTRL_CONFIG);

	dma_free_coherent(&ctrl->dev, ctrl->dma_size, ctrl->dma_buf0,
			  ctrl->dma_handle0);
	dma_free_coherent(&ctrl->dev, ctrl->dma_size, ctrl->dma_buf1,
			  ctrl->dma_handle1);

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
