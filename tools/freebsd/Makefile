
UNAME_I!=	/usr/bin/uname -i
UNAME_M!=	/usr/bin/uname -m
UNAME_R!=	/usr/bin/uname -r
UNAME_S!=	/usr/bin/uname -s
BOOTFILE!=	/sbin/sysctl -n kern.bootfile
CLEANFILES=	freebsd-kernel.map ${KMOD}.dwarf ${UNAME_S}-${UNAME_R}-${UNAME_I}-${UNAME_M}.zip

SRCS=		module.c vnode_if.h
KMOD=		module
DEBUG_FLAGS=	-g
SYSDIR?=	/usr/src/sys
PAE!=		/sbin/sysctl -i -n kern.features.pae
PAEMODE!=	/sbin/sysctl -n vm.pmap.pae_mode 2>/dev/null || echo nope
VIMAGE!=	/sbin/sysctl -i -n kern.features.vimage

.if ${PAE} == 1
CFLAGS+=	-DPAE=1
.endif

.if ${PAEMODE} == 0
CFLAGS+=	-DPAEMODE=0
.elif ${PAEMODE} == 1
CFLAGS+=	-DPAEMODE=1
.endif

.if ${VIMAGE} == 1
CFLAGS+=	-DVIMAGE=1
.endif

${KMOD}.dwarf:	${KMOD}.ko.debug
	/usr/local/bin/dwarfdump -di ${KMOD}.ko.debug > ${.TARGET}

freebsd-kernel.map:	${BOOTFILE}
	/usr/bin/nm ${BOOTFILE} > ${.TARGET}

${UNAME_S}-${UNAME_R}-${UNAME_I}-${UNAME_M}.zip:	freebsd-kernel.map ${KMOD}.dwarf
	/usr/local/bin/zip -r ${.TARGET} freebsd-kernel.map ${KMOD}.dwarf

all:	${UNAME_S}-${UNAME_R}-${UNAME_I}-${UNAME_M}.zip

.include <bsd.kmod.mk>
