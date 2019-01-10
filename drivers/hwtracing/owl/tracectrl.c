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

#define DRV_NAME "riscv-tracectrl"

#define TRACECTRL_CONFIG	0x00 /* config register */
#define TRACECTRL_STATUS	0x04 /* status register */
#define TRACECTRL_BUF0_ADDR	0x10 /* base address of trace buffer 0 */
#define TRACECTRL_BUF0_MASK	0x18 /* mask size of trace buffer 0 */


struct tracectrl {
	void __iomem *base_addr;
	spinlock_t lock;
	void *dma_buf;
	dma_addr_t dma_handle;
	size_t dma_size;
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
	struct resource *res;

	ctrl = devm_kzalloc(&pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	platform_set_drvdata(pdev, ctrl);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ctrl->base_addr = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ctrl->base_addr))
		return PTR_ERR(ctrl->base_addr);

	spin_lock_init(&ctrl->lock);

	/* TODO: Allocate buffer on user request, i.e., not here ... */
	ctrl->dma_size = SZ_64K;
	ctrl->dma_buf = dma_alloc_coherent(&pdev->dev, ctrl->dma_size,
					   &ctrl->dma_handle, GFP_KERNEL);
	if (!ctrl->dma_buf)
		return -ENOMEM;

	/* TODO: 64 bit write ... */
	tracectrl_reg_write((u32) ctrl->dma_handle & 0xffffffff,
			    ctrl, TRACECTRL_BUF0_ADDR);
	tracectrl_reg_write((u32) ((long) ctrl->dma_handle >> 32) & 0xffffffff,
			    ctrl, TRACECTRL_BUF0_ADDR + 4);
	tracectrl_reg_write(ctrl->dma_size - 1, ctrl, TRACECTRL_BUF0_MASK);
	tracectrl_reg_write(0, ctrl, TRACECTRL_BUF0_MASK + 4);

	/* HACK: Enable trace ctrl. Should be user knob */
	tracectrl_reg_write(1, ctrl, TRACECTRL_CONFIG);

	return 0;
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

	/* Disable tracing */
	tracectrl_reg_write(0, ctrl, TRACECTRL_CONFIG);

	dma_free_coherent(&pdev->dev, ctrl->dma_size, ctrl->dma_buf,
			  ctrl->dma_handle);

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
module_platform_driver(tracectrl_driver);

MODULE_AUTHOR("Ola Jeppsson <ola.jeppsson@gmail.com>");
MODULE_DESCRIPTION("OWL TraceCtrl driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
