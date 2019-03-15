/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_MMAP_NOTIFIER_H
#define __LINUX_MMAP_NOTIFIER_H

#ifdef CONFIG_MMAP_NOTIFIERS

struct mmap_notifier;

/**
 * mmap_notifier_ops - notifiers called when a mmap event occurs.
 * @mmap: mmap event callback:
 *    notifier: struct mmap_notifier for the task being scheduled
 *    vma: the vm area
 */
struct mmap_notifier_ops {
	void (*mmap)(struct mmap_notifier *notifier,
		     struct vm_area_struct *vma);
};

/**
 * mmap_notifier - key for installing mmap notifiers
 * @link: internal use
 * @ops: defines the notifier functions to be called
 *
 * Usually used in conjunction with container_of().
 */
struct mmap_notifier {
	struct hlist_node link;
	struct mmap_notifier_ops *ops;
};

void mmap_notifier_inc(void);
void mmap_notifier_dec(void);
void mmap_notifier_register(struct mmap_notifier *notifier);
void mmap_notifier_unregister(struct mmap_notifier *notifier);

static inline void mmap_notifier_init(struct mmap_notifier *notifier,
				      struct mmap_notifier_ops *ops)
{
	INIT_HLIST_NODE(&notifier->link);
	notifier->ops = ops;
}

#endif /* CONFIG_MMAP_NOTIFIERS */

#endif /* __LINUX_MMAP_NOTIFIER_H */
