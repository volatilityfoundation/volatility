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
#include <linux/fdtable.h>
#include <net/ip_fib.h>
#include <net/af_unix.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/radix-tree.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

struct uts_namespace uts_namespace;
struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;
struct pid pid;
struct pid_namespace pid_namespace;
struct radix_tree_root radix_tree_root;
#ifdef CONFIG_NETFILTER
struct nf_hook_ops nf_hook_ops;
struct nf_sockopt_ops nf_sockopt_ops;
#endif

struct xt_table xt_table;

/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
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


#define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_TAG_LONGS    ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    struct rcu_head rcu_head;
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};


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

#ifdef CONFIG_SLAB

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
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


