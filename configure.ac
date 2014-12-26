AC_PREREQ([2.68])
AC_INIT([tgl], [0.1])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([
    check-news
    foreign
    1.11
    -Wall
    -Wno-portability
    silent-rules
    tar-pax
    no-dist-gzip
    dist-xz
    subdir-objects
])

AC_PROG_MAKE_SET


m4_include([m4_ax_check_openssl.m4])
m4_include([m4_ax_check_zlib.m4])
m4_include([m4-ax_gcc_builtin.m4])

AC_CONFIG_MACRO_DIR([m4])
LT_INIT
AM_CONDITIONAL([TARGET_LINUX],[test "${host_os}" = "linux-gnu" ||
                 test "${host_os}" = "linux"])
# Checks for programs.
AC_PROG_CC


# BSD locations for headers and libraries from packages, Linux locations for self-compiled stuff.
CPPFLAGS="$CPPFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_SEARCH_LIBS([clock_gettime], [rt])

EVENT_VER=""
EXTRA_OBJECTS=""

#     OPENSSL_INCLUDES to the include directives required
#     OPENSSL_LIBS to the -l directives required
#     OPENSSL_LDFLAGS to the -L or -R flags required

AX_CHECK_OPENSSL(,[AC_MSG_ERROR([No openssl found])])
AX_CHECK_ZLIB(, [AC_MSG_ERROR([No zlib found])])

AC_ARG_ENABLE(extf,[enables extended queries system],
  [ 
  if test "x$enableval" = "xno" ; then    
    AC_DEFINE([DISABLE_EXTF],[1],[disable extf queries])
  fi 
  ],[
  ])

AC_ARG_ENABLE(libevent,[include libevent-based net and timers],
  [ 
  if test "x$enableval" = "xyes" ; then
    AC_CHECK_LIB([event], [event_base_new], [], [AC_MSG_ERROR([no libevent found])])
    AC_CHECK_HEADER(event2/event.h, [AC_DEFINE([EVENT_V2], [1], [Use libevent v2])], [
      AC_CHECK_HEADER(event.h, [AC_DEFINE([EVENT_V1], [1], [Use libevent v1])], [AC_MSG_ERROR([no libevent found])])
    ])
    EXTRA_OBJECTS='tgl-net.lo tgl-timers.lo'
  fi
  ],[
  ])
    
# Checks for header files.
AC_CHECK_HEADERS([execinfo.h fcntl.h malloc.h netdb.h stdlib.h string.h unistd.h arpa/inet.h mach/mach.h netinet/in.h sys/file.h sys/socket.h termios.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm endpwent memset memmove mkdir select socket strdup strndup uname])

AX_GCC_BUILTIN(__builtin_bswap32)

AC_SUBST(EXTRA_LIBS)
AC_SUBST([EXTRA_OBJECTS])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

