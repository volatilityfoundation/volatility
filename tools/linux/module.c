/*
  This module does absolutely nothings at all. We just build it with debugging
symbols and then read the DWARF symbols from it.
*/
#include <linux/module.h>
#include <linux/version.h>

#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/udp.h>
#include <linux/mount.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#include <linux/lockref.h>
struct lockref lockref;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#else
#include <linux/file.h>
#endif

#include <net/ip_fib.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/pid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/pid_namespace.h>
struct pid_namespace pid_namespace;
#endif


#ifdef CONFIG_NETFILTER
#include <linux/netfilter.h>

struct nf_hook_ops nf_hook_ops;
struct nf_sockopt_ops nf_sockopt_ops;

#ifdef CONFIG_NETFILTER_XTABLES
#include <linux/netfilter/x_tables.h>
struct xt_table xt_table;
#endif

#endif

#include <linux/radix-tree.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/termios.h>
#include <asm/termbits.h>

#include <linux/notifier.h>
struct atomic_notifier_head atomic_notifier_head;

#include <linux/tty_driver.h>
struct tty_driver tty_driver;

#include <linux/tty.h>
struct tty_struct tty_struct;

struct udp_seq_afinfo udp_seq_afinfo;
struct tcp_seq_afinfo tcp_seq_afinfo;

struct files_struct files_struct;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
struct uts_namespace uts_namespace;
#endif

struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;
struct pid pid;
struct radix_tree_root radix_tree_root;

#ifdef CONFIG_NET_SCHED
#include <net/sch_generic.h>
struct Qdisc qdisc;
#endif

struct inet_protosw inet_protosw;

/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

struct kthread_create_info
{
     /* Information passed to kthread() from kthreadd. */
     int (*threadfn)(void *data);
     void *data;
     int node;

     /* Result passed back to kthread_create() from kthreadd. */
     struct task_struct *result;
     struct completion done;

     struct list_head list;
};

struct kthread_create_info kthread_create_info;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#include <net/ip.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <linux/compiler.h>

#define EMBEDDED_HASH_SIZE (L1_CACHE_BYTES / sizeof(struct hlist_head))

#define __rcu

struct fn_zone {
  struct fn_zone     *fz_next;       /* Next not empty zone  */
  struct hlist_head  *fz_hash;       /* Hash table pointer   */
  seqlock_t               fz_lock;
  u32                     fz_hashmask;    /* (fz_divisor - 1)     */
  u8                      fz_order;       /* Zone order (0..32)   */
  u8                      fz_revorder;    /* 32 - fz_order        */
  __be32                  fz_mask;        /* inet_make_mask(order) */

  struct hlist_head       fz_embedded_hash[EMBEDDED_HASH_SIZE];

  int                     fz_nent;        /* Number of entries    */
  int                     fz_divisor;     /* Hash size (mask+1)   */
} fn_zone;

struct fn_hash {
  struct fn_zone    *fn_zones[33];
  struct fn_zone    *fn_zone_list;
} fn_hash;

struct fib_alias 
{
    struct list_head        fa_list;
    struct fib_info         *fa_info;
    u8                      fa_tos;
    u8                      fa_type;
    u8                      fa_scope;
    u8                      fa_state;
#ifdef CONFIG_IP_FIB_TRIE
        struct rcu_head         rcu;
#endif
};

struct fib_node 
{
    struct hlist_node       fn_hash;
    struct list_head        fn_alias;
    __be32                  fn_key;
    struct fib_alias        fn_embedded_alias;
};


struct fib_node fib_node;
struct fib_alias fib_alias;

struct rt_hash_bucket {
  struct rtable __rcu     *chain;
} rt_hash_bucket;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_TAG_LONGS    ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define RADIX_TREE_MAX_TAGS     2

struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    struct rcu_head rcu_head;
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
struct module_sect_attr
{
        struct module_attribute mattr;
        char *name;
        unsigned long address;
};

struct module_sect_attrs
{
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
};

struct module_sect_attrs module_sect_attrs;

#else

struct module_sections module_sect_attrs;

#endif

struct module_kobject module_kobject;

#ifdef CONFIG_SLAB

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/*
 * struct kmem_cache
 *
 * manages a cache.
 */

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int buffer_size;
	u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *slabp_cache;
	unsigned int slab_size;
	unsigned int dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(void *obj);

/* 5) cache creation/removal */
	const char *name;
	struct list_head next;

/* 6) statistics */
#if STATS
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#endif
#if DEBUG
	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. buffer_size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
	int obj_size;
#endif
	/*
	 * We put nodelists[] at the end of kmem_cache, because we want to size
	 * this array to nr_node_ids slots instead of MAX_NUMNODES
	 * (see kmem_cache_init())
	 * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of nodes.
	 */
	struct kmem_list3 *nodelists[MAX_NUMNODES];
	/*
	 * Do not add fields after nodelists[]
	 */
};
#else

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
        struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;

        unsigned int buffer_size;
/* 3) touched by every alloc & free from the backend */
        struct kmem_list3 *nodelists[MAX_NUMNODES];

        unsigned int flags;             /* constant flags */
        unsigned int num;               /* # of objs per slab */

/* 4) cache_grow/shrink */
        /* order of pgs per slab (2^n) */
        unsigned int gfporder;

        /* force GFP flags, e.g. GFP_DMA */
        gfp_t gfpflags;

        size_t colour;                  /* cache colouring range */
        unsigned int colour_off;        /* colour offset */
        struct kmem_cache *slabp_cache;
        unsigned int slab_size;
        unsigned int dflags;            /* dynamic flags */

        /* constructor func */
        void (*ctor) (void *, struct kmem_cache *, unsigned long);

        /* de-constructor func */
        void (*dtor) (void *, struct kmem_cache *, unsigned long);

/* 5) cache creation/removal */
        const char *name;
        struct list_head next;

/* 6) statistics */
#if STATS
        unsigned long num_active;
        unsigned long num_allocations;
        unsigned long high_mark;
        unsigned long grown;
        unsigned long reaped;
        unsigned long errors;
        unsigned long max_freeable;
        unsigned long node_allocs;
        unsigned long node_frees;
        unsigned long node_overflow;
        atomic_t allochit;
        atomic_t allocmiss;
        atomic_t freehit;
        atomic_t freemiss;
#endif
#if DEBUG
        /*
         * If debugging is enabled, then the allocator can add additional
         * fields and/or padding to every object. buffer_size contains the total
         * object size including these internal fields, the following two
         * variables contain the offset to the user object and its size.
         */
        int obj_offset;
        int obj_size;
#endif
};

#endif /*kmem_cache decl*/

struct kmem_cache kmem_cache;
#endif

struct kmem_list3 {
         struct list_head slabs_partial; /* partial list first, better asm code */
         struct list_head slabs_full;
         struct list_head slabs_free;
        unsigned long free_objects;
         unsigned int free_limit;
         unsigned int colour_next;       /* Per-node cache coloring */
         spinlock_t list_lock;
         struct array_cache *shared;     /* shared per node */
         struct array_cache **alien;     /* on other nodes */
         unsigned long next_reap;        /* updated without locking */
         int free_touched;               /* updated without locking */
};

struct kmem_list3 kmem_list3;

struct slab {         
     struct list_head list;
     unsigned long colouroff;
     void *s_mem;            /* including colour offset */
     unsigned int inuse;     /* num of objs active in slab */
     unsigned int free;
     unsigned short nodeid;          
 };
 
struct slab slab;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)

typedef u64 cycle_t;

struct timekeeper {
	/* Current clocksource used for timekeeping. */
	struct clocksource *clock;
	/* NTP adjusted clock multiplier */
	u32	mult;
	/* The shift value of the current clocksource. */
	int	shift;

	/* Number of clock cycles in one NTP interval. */
	cycle_t cycle_interval;
	/* Number of clock shifted nano seconds in one NTP interval. */
	u64	xtime_interval;
	/* shifted nano seconds left over when rounding cycle_interval */
	s64	xtime_remainder;
	/* Raw nano seconds accumulated per NTP interval. */
	u32	raw_interval;

	/* Clock shifted nano seconds remainder not stored in xtime.tv_nsec. */
	u64	xtime_nsec;
	/* Difference between accumulated time and NTP time in ntp
	 * shifted nano seconds. */
	s64	ntp_error;
	/* Shift conversion between clock shifted nano seconds and
	 * ntp shifted nano seconds. */
	int	ntp_error_shift;

	/* The current time */
	struct timespec xtime;
	/*
	 * wall_to_monotonic is what we need to add to xtime (or xtime corrected
	 * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
	 * at zero at system boot time, so wall_to_monotonic will be negative,
	 * however, we will ALWAYS keep the tv_nsec part positive so we can use
	 * the usual normalization.
	 *
	 * wall_to_monotonic is moved after resume from suspend for the
	 * monotonic time not to jump. We need to add total_sleep_time to
	 * wall_to_monotonic to get the real boot based time offset.
	 *
	 * - wall_to_monotonic is no longer the boot time, getboottime must be
	 * used instead.
	 */
	struct timespec wall_to_monotonic;
	/* time spent in suspend */
	struct timespec total_sleep_time;
	/* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
	struct timespec raw_time;

	/* Offset clock monotonic -> clock realtime */
	ktime_t offs_real;

	/* Offset clock monotonic -> clock boottime */
	ktime_t offs_boot;

	/* Seqlock for all timekeeper values */
	seqlock_t lock;
};


struct timekeeper my_timekeeper;

struct log {
         u64 ts_nsec;            /* timestamp in nanoseconds */
         u16 len;                /* length of entire record */
         u16 text_len;           /* length of text buffer */
         u16 dict_len;           /* length of dictionary buffer */
         u8 facility;            /* syslog facility */
         u8 flags:5;             /* internal record flags */
         u8 level:3;             /* syslog level */
};

struct log my_log;

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)

struct mnt_namespace {
	atomic_t		count;
	struct mount *	root;
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
	struct list_head mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
        struct callback_head rcu;
#endif
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_t mnt_longterm;		/* how many of the refs are longterm */
#endif
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	int mnt_ghosts;
};

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next, *parent, *subdir;
    void *data;
    atomic_t count;         /* use count */
    atomic_t in_use;        /* number of callers into module in progress; */
                          /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};
#endif

