#ifndef _OWL_H_
#define _OWL_H_

#include <linux/types.h>
#include <linux/ioctl.h>

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
	__u64 tracebuf_size;
	__u64 metadata_size;
	__u64 map_info_size;
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
	__u32 clock_divider; /* How many clocks per tick */
	union {
		/* TODO: Decide on which one to use. Seems LvNA Linux are
		 * working on mapping dsid to cgroup. */
		__kernel_pid_t dsid;
		__kernel_pid_t ppid;
		__kernel_pid_t cgroup;
	};
	bool ignore_illegal_insn; /* Don't trace illegal instructions */
};

#define OWL_TRACE_KIND_UECALL		0x0 /* Usermode ecall */
#define OWL_TRACE_KIND_RETURN		0x1 /* Return from ecall/exception */
#define OWL_TRACE_KIND_SECALL		0x2 /* Supervisor ecall */
#define OWL_TRACE_KIND_TIMESTAMP	0x3 /* Full 61-bit timestamp */
#define OWL_TRACE_KIND_EXCEPTION	0x4 /* Non-ecall exception/interrupt */
#define OWL_TRACE_KIND_PCHI		0x5 /* High bits of PC */

struct owl_ecall_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned regval:11;
} __attribute__((packed));

struct owl_return_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned regval:11;
	unsigned pc:32;
} __attribute__((packed));

struct owl_exception_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned cause:8;
	unsigned :3; /* reserved */
} __attribute__((packed));

struct owl_timestamp_trace {
	unsigned kind:3;
	__u64 timestamp:61;
} __attribute__((packed));

struct owl_pchi_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned priv:2;
	unsigned :9 /* reserved */;
	unsigned pchi:32; /* Not sign extended */
} __attribute__((packed));


union owl_trace {
	__u64 val;
	struct {
		unsigned kind:3;
		unsigned lsb_timestamp:18;
	} __attribute__((packed));
	struct owl_ecall_trace ecall;
	struct owl_return_trace ret;
	struct owl_exception_trace exception;
	struct owl_timestamp_trace timestamp;
	struct owl_pchi_trace pchi;
} __attribute__((packed));


#define OWL_TASK_COMM_LEN 16
struct owl_task {
	int		pid;
	int		ppid;
	/* TODO: 1. Use hashtable with exe inode. Will be lots of duplicates */
	char		comm[OWL_TASK_COMM_LEN];
} __attribute__((packed));

struct owl_metadata_entry {
	__u64		timestamp; /* use relative to save space */
	__u16		cpu; /* 65536 cpus should be enough for now */
	unsigned	has_mm:1;
	unsigned	in_execve:1;
	unsigned	kthread:1;
	__u64		:45; /* pad */
	struct owl_task	task;
} __attribute__((packed));

#define OWL_PATH_MAX 128
struct owl_map_info {
	char path[OWL_PATH_MAX]; /* TODO: Convert to offset into string table */
	int pid;
	__u64 vm_start;
	__u64 vm_end;
} __attribute__((packed));

struct owl_trace_header {
	/* Filled in by user */
	void __user *tracebuf;		/* Buffer for traces */
	void __user *metadatabuf;	/* Buffer for meta data */
	void __user *mapinfobuf;	/* Buffer for map info */
	__u64 max_tracebuf_size;
	__u64 max_metadata_size;
	__u64 max_map_info_size;

	/* Filled in by kernel */
	enum owl_trace_format trace_format;
	enum owl_metadata_format metadata_format;
	__u64 tracebuf_size;	/* Size of trace buffer */
	__u64 metadata_size;	/* Size of metadata */
	__u64 map_info_size;	/* Size of mapping info */
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
