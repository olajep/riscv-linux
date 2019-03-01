#ifndef _OWL_H_
#define _OWL_H_

#include <linux/types.h>
#include <asm/ioctl.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct owl_status {
	int enabled;
	union {
		/* TODO: Decide on which one to use. Seems LvNA Linux are
		 * working on mapping dsid to cgroup. */
		__kernel_pid_t dsid;
		__kernel_pid_t ppid;
		__kernel_pid_t cgroup;
	};
	u64 tracebuf_size;
	u64 metadatabuf_size;
};

enum owl_trace_format {
	OWL_TRACE_FORMAT_DEFAULT,
};

enum owl_metadata_format {
	OWL_METADATA_FORMAT_DEFAULT,
};

struct owl_config {
	enum owl_trace_format trace_format;
	enum owl_metadata_format metadata_format; /* ??? Do we need this */
	u32 clock_divider; /* How many clocks per tick */
	union {
		/* TODO: Decide on which one to use. Seems LvNA Linux are
		 * working on mapping dsid to cgroup. */
		__kernel_pid_t dsid;
		__kernel_pid_t ppid;
		__kernel_pid_t cgroup;
	};
};

struct owl_trace_entry_default {
	unsigned timestamp:20; /* relative timestamp */
	unsigned syscall:10; /* which syscall */
	unsigned priv:2; /* user, kernel, supervisor */
} __packed;

struct owl_metadata_entry {
	u64 str_offset; /* Offset from owl_trace_header->metadata to exec string */
	unsigned timestamp:20; /* When process was scheduled in */
	/* Map ??? */
	/* u64 text_offset //  ???: If we wan't the user space callsite */
};

struct owl_trace_header {
	/* Filled in by user */
	void __user *tracebuf;		/* Buffer for traces */
	void __user *metadatabuf;	/* Buffer for meta data */
	u64 tracebuf_size;
	u64 metadatabuf_size;

	/* Filled in by kernel */
	enum owl_trace_format trace_format;
	enum owl_metadata_format metadata_format;
	u64 trace_entries;	/* Number of trace entries */
	u64 metadata_entries;	/* Number of kernel meta data entries */
};

#define OWL_IOCTL_BASE			'o'
#define OWL_IO(nr)			_IO(OWL_IOCTL_BASE,nr)
#define OWL_IOR(nr,type)		_IOR(OWL_IOCTL_BASE,nr,type)
#define OWL_IOW(nr,type)		_IOW(OWL_IOCTL_BASE,nr,type)
#define OWL_IOWR(nr,type)		_IOWR(OWL_IOCTL_BASE,nr,type)

#define OWL_IOCTL_STATUS		OWL_IOR( 0x00, struct owl_status)
#define OWL_IOCTL_CONFIG		OWL_IOW( 0x01, struct owl_config)
#define OWL_IOCTL_ENABLE		OWL_IO(  0x02)
#define OWL_IOCTL_DISABLE		OWL_IO(  0x03)
#define OWL_IOCTL_DUMP			OWL_IOWR(0x04, struct owl_trace_header)

#if defined(__cplusplus)
}
#endif

#endif
