EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

##bin_PROGRAMS = tgl_generate

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I${top_srcdir} @CPPFLAGS@ @OPENSSL_INCLUDES@

AM_CFLAGS = ${my_CFLAGS} \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-deprecated-declarations \
	-fno-strict-aliasing \
	-fno-omit-frame-pointer \
	-ggdb \
	-Wno-unused-parameter \
	-fPIC \
	@CFLAGS@

AM_LDFLAGS = \
	-Wl,--gc-sections \
	@LDFLAGS@


LIBTGL_CURRENT=1
LIBTGL_REVISION=0
LIBTGL_AGE=1

##include ${top_srcdir}/Makefile.tl-parser

pkginclude_HEADERS = tgl.h tgl-layout.h
lib_LTLIBRARIES = libtgl.la

libtgl_la_SOURCES =\
	auto/auto.c \
	auto/constants.h \
	auto/auto-header.h \
	binlog.c \
	mtproto-client.c \
	mtproto-common.c \
	queries.c \
	structures.c \
	tg-mime-types.c \
	tgl-serialize.c \
	tgl.c \
	tgl.h \
	updates.c \
	tools.c

libtgl_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBTGL_CURRENT):$(LIBTGL_REVISION):$(LIBTGL_AGE) \
	@OPENSSL_LIBS@ @OPENSSL_LDFLAGS@

##tgl_generate_SOURCES = \
##	generate.c \
##	tools.c
