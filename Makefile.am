EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

noinst_PROGRAMS = tgl-generate tgl-tl-parser ##dump-tl-file

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
	-fPIC

AM_LDFLAGS = \
	-Wl,--gc-sections


LIBTGL_CURRENT=1
LIBTGL_REVISION=0
LIBTGL_AGE=1

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
	tgl-layout.h \
	updates.c \
	tools.c

libtgl_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBTGL_CURRENT):$(LIBTGL_REVISION):$(LIBTGL_AGE) \
	$(OPENSSL_LIBS) $(OPENSSL_LDFLAGS)

tgl_generate_SOURCES = \
	generate.c \
	tools.c

## noop to avoid libtool error ‘created with both libtool and without’
tgl_generate_CFLAGS = $(AM_CFLAGS)
tgl_generate_LDFLAGS = $(OPENSSL_LIBS)


tgl_tl_parser_SOURCES = tl-parser/tl-parser.c \
					tl-parser/tlc.c \
					tl-parser/crc32.c
tgl_tl_parser_CFLAGS = -iquote

auto/scheme.tlo: auto/scheme.tl tgl-tl-parser
	${srcdir}/tgl-tl-parser -e $@ auto/scheme.tl

auto/scheme.tl: ${srcdir}/scheme.tl ${srcdir}/encrypted_scheme.tl \
		${srcdir}/binlog.tl ${srcdir}/append.tl
		cat $^ > $@

auto/scheme2.tl: auto/scheme.tl tgl-tl-parser
	${srcdir}/tgl-tl-parser -E auto/scheme.tl 2> $@  || ( cat 	$@ && rm $@ && false )

auto/auto.c: auto/scheme.tlo tgl-generate
	${srcdir}/tgl-generate auto/scheme.tlo > $@

auto/auto-header.h: auto/scheme.tlo tgl-generate
	${srcdir}/tgl-generate -H auto/scheme.tlo > $@

auto/constants.h: auto/scheme2.tl ${srcdir}/gen_constants_h.awk
	awk -f ${srcdir}/gen_constants_h.awk < $< > $@


###dump_tl_file_SOURCES = auto/auto.c dump-tl-file.c
###dump_tl_file_CFLAGS = $(AM_CFLAGS)

