/*-
 * This file is in the public domain.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/conf.h>		/* cdev */
#include <sys/exec.h>		/* ps_strings */
#include <sys/filedesc.h>	/* filedesc, fdescenttbl, filedescent */
#include <sys/file.h>		/* file */
#include <sys/linker.h>		/* linker_file */
#include <sys/module.h>		/* modeventhand_t, modspecific_t */
#include <sys/mount.h>		/* mntlist, mount */
#include <sys/proc.h>		/* pgrp, proc, proclist, session, thread */
#include <sys/queue.h>
#include <sys/socket.h>		/* sockaddr */
#include <sys/socketvar.h>	/* socket */
#include <sys/domain.h>		/* domain */
#include <sys/protosw.h>	/* protosw */
#include <sys/un.h>		/* sockaddr_un */
#include <sys/unpcb.h>		/* unpcb */
#include <sys/sysent.h>		/* sysentvec */
#include <sys/tty.h>		/* tty */
#include <sys/ucred.h>		/* ucred */
#include <sys/vnode.h>		/* vnode */

#include <net/if.h>
#include <net/if_var.h>		/* ifnethead, ifnet, ifaddrhead, ifaddr */
#include <net/vnet.h>		/* vnet */

#include <netinet/in.h>		/* sockaddr_in, sockaddr_in6 */
#include <netinet/in_pcb.h>	/* inpcb */

#include <vm/vm.h>
#include <vm/vm_param.h>
#if defined(__i386__)
#if defined(PAEMODE) && PAEMODE == 0
#define	PMTYPE	pmap_nopae_
#include <machine/pmap_nopae.h>
#elif defined(PAEMODE) && PAEMODE == 1
#define	PMTYPE	pmap_pae_
#include <machine/pmap_pae.h>
#endif
#endif
#include <vm/pmap.h>		/* pmap */
#include <vm/vm_map.h>		/* vm_map_entry, vmspace */
#include <vm/vm_object.h>	/* vm_object */

#if defined(__amd64__)
#include <compat/freebsd32/freebsd32_util.h>	/* freebsd32_ps_strings */
#endif

struct cdev vol_cdev;

struct ps_strings vol_ps_strings;
#if defined(__amd64__)
struct freebsd32_ps_strings vol_freebsd32_ps_strings;
#endif

struct fdescenttbl vol_fdescenttbl;
struct filedesc vol_filedesc;
struct filedescent vol_filedescent;

struct file vol_file;

struct linker_file vol_linker_file;
TAILQ_HEAD(linker_file_head, linker_file);
struct linker_file_head vol_linker_file_head;

struct module {
	TAILQ_ENTRY(module)	link;
	TAILQ_ENTRY(module)	flink;
	struct linker_file	*file;
	int			refs;
	int			id;
	char			*name;
	modeventhand_t		handler;
	void			*arg;
	modspecific_t		data;
};
struct module vol_module;
TAILQ_HEAD(modulelist, module);
struct modulelist vol_modulelist;

struct mntlist vol_mntlist;
struct mount vol_mount;

struct pgrp vol_pgrp;
struct proc vol_proc;
struct proclist vol_proclist;
struct session vol_session;
struct thread vol_thread;

struct sockaddr vol_sockaddr;
struct socket vol_socket;
struct domain vol_domain;
struct protosw vol_protosw;
struct sockaddr_un vol_sockaddr_un;
struct unpcb vol_unpcb;

struct sysentvec vol_sysentvec;

struct tty vol_tty;

struct ucred vol_ucred;

struct vnode vol_vnode;

struct namecache {
	LIST_ENTRY(namecache)	nc_hash;
	LIST_ENTRY(namecache)	nc_src;
	TAILQ_ENTRY(namecache)	nc_dst;
	struct vnode		*nc_dvp;
	union {
		struct vnode	*nu_vp;
		u_int		nu_neghits;
	} n_un;
	u_char			nc_flag;
	u_char			nc_nlen;
	char			nc_name[0];
};
struct namecache vol_namecache;

struct ifnethead vol_ifnethead;
struct ifnet vol_ifnet;
struct ifaddrhead vol_ifaddrhead;
struct ifaddr vol_ifaddr;

struct vnet vol_vnet;
#if defined(VIMAGE)
struct vnet_list_head vol_vnet_list_head;
#endif

struct sockaddr_in vol_sockaddr_in;
struct sockaddr_in6 vol_sockaddr_in6;
struct inpcb vol_inpcb;

struct pmap vol_pmap;
struct vm_map_entry vol_vm_map_entry;
struct vmspace vol_vmspace;
struct vm_object vol_vm_object;

