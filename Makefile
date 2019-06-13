#	$OpenBSD: Makefile,v 1.47 2018/07/03 01:34:43 mortimer Exp $

PROG=	dane

BINDIR=	/usr/local/bin
NOMAN=

CFLAGS+=	-fstack-protector-all
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	-Werror-implicit-function-declaration
CFLAGS+=	-DNO_IO
CFLAGS+=	-DCONFIG_MINIMUM
YFLAGS=

SRCS=	dane.c
SRCS+=	unpack_dns.c

LDADD+=	-levent -lssl -lcrypto
DPADD+=	${LIBEVENT} ${LIBSSL} ${LIBCRYPTO}
.include <bsd.prog.mk>
