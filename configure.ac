dnl Process this file with autoconf to produce a configure script
AC_INIT([openbsc],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl check for AX_CHECK_COMPILE_FLAG
m4_ifdef([AX_CHECK_COMPILE_FLAG], [], [
	AC_MSG_ERROR([Please install autoconf-archive; re-run 'autoreconf -fi' for it to take effect.])
	])

dnl checks for libraries
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DL="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DL)


PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.2.0)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.0.1)
PKG_CHECK_MODULES(LIBOSMOSIGTRAN, libosmo-sigtran) # TODO version?
PKG_CHECK_MODULES(LIBCRYPTO, libcrypto >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOLEGACYMGCP, libosmo-legacy-mgcp >= 0.0.1)

# Enable/disable smpp support in the msc?
AC_ARG_ENABLE([smpp], [AS_HELP_STRING([--enable-smpp], [Build the SMPP interface])],
    [osmo_ac_build_smpp="$enableval"],[osmo_ac_build_smpp="no"])
if test "$osmo_ac_build_smpp" = "yes" ; then
    PKG_CHECK_MODULES(LIBSMPP34, libsmpp34 >= 1.12)
    AC_DEFINE(BUILD_SMPP, 1, [Define if we want to build SMPP])
fi
AM_CONDITIONAL(BUILD_SMPP, test "x$osmo_ac_build_smpp" = "xyes")
AC_SUBST(osmo_ac_build_smpp)

# Enable/disable transcoding within osmo-bsc_mgcp?
AC_ARG_ENABLE([mgcp-transcoding], [AS_HELP_STRING([--enable-mgcp-transcoding], [Build the MGCP gateway with internal transcoding enabled.])],
    [osmo_ac_mgcp_transcoding="$enableval"],[osmo_ac_mgcp_transcoding="no"])
AC_ARG_WITH([g729], [AS_HELP_STRING([--with-g729], [Enable G.729 encoding/decoding.])], [osmo_ac_with_g729="$withval"],[osmo_ac_with_g729="no"])

# Enable/disable 3G aka IuPS + IuCS support?
AC_ARG_ENABLE([iu], [AS_HELP_STRING([--enable-iu], [Build 3G support, aka IuPS and IuCS interfaces])],
    [osmo_ac_iu="$enableval"],[osmo_ac_iu="no"])
if test "x$osmo_ac_iu" = "xyes" ; then
    PKG_CHECK_MODULES(LIBASN1C, libasn1c) # TODO version?
    PKG_CHECK_MODULES(LIBOSMORANAP, libosmo-ranap) # TODO version?
    AC_DEFINE(BUILD_IU, 1, [Define if we want to build IuPS and IuCS interfaces support])
fi
AM_CONDITIONAL(BUILD_IU, test "x$osmo_ac_iu" = "xyes")
AC_SUBST(osmo_ac_iu)

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(dbi/dbd.h,,AC_MSG_ERROR(DBI library is not installed))

found_pcap=yes
AC_CHECK_HEADERS(pcap/pcap.h,,found_pcap=no)
AM_CONDITIONAL(HAVE_PCAP, test "$found_pcap" = yes)

found_cdk=yes
AC_CHECK_HEADERS(cdk/cdk.h,,found_cdk=no)
AM_CONDITIONAL(HAVE_LIBCDK, test "$found_cdk" = yes)

found_sqlite3=yes
PKG_CHECK_MODULES(SQLITE3, sqlite3, ,found_sqlite3=no)
AM_CONDITIONAL(HAVE_SQLITE3, test "$found_sqlite3" = yes)
AC_SUBST(found_sqlite3)


dnl Checks for typedefs, structures and compiler characteristics

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AX_CHECK_COMPILE_FLAG([-Werror=implicit], [CFLAGS="$CFLAGS -Werror=implicit"])
AX_CHECK_COMPILE_FLAG([-Werror=maybe-uninitialized], [CFLAGS="$CFLAGS -Werror=maybe-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Werror=memset-transposed-args], [CFLAGS="$CFLAGS -Werror=memset-transposed-args"])
AX_CHECK_COMPILE_FLAG([-Werror=null-dereference], [CFLAGS="$CFLAGS -Werror=null-dereference"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-array-argument], [CFLAGS="$CFLAGS -Werror=sizeof-array-argument"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-pointer-memaccess], [CFLAGS="$CFLAGS -Werror=sizeof-pointer-memaccess"])

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi

AC_DEFUN([CHECK_LIBOSMO_LEGACY_MGCP_NEEDS_LIBGSM], [
  AC_CACHE_CHECK(
    [whether libosmo-legacy-mgcp needs -lgsm],
    libosmo_cv_legacy_mgcp_needs_libgsm, [
       SAVE_LDFLAGS="${LDFLAGS}"
       LDFLAGS="${LIBOSMOLEGACYMGCP_LIBS} ${LIBOSMOVTY_LIBS}"
       AC_LINK_IFELSE(
         [AC_LANG_PROGRAM([
                           #include <osmocom/legacy_mgcp/mgcpgw_client.h>
                         ], [
                           mgcpgw_client_init(0, 0);
                         ])],
         [libosmo_cv_legacy_mgcp_needs_libgsm=no],
         [libosmo_cv_legacy_mgcp_needs_libgsm=yes])
       LDFLAGS="${SAVE_LDFLAGS}"
       ])
  ])
CHECK_LIBOSMO_LEGACY_MGCP_NEEDS_LIBGSM
if test "x$libosmo_cv_legacy_mgcp_needs_libgsm" = xyes; then
    AC_SEARCH_LIBS([gsm_create], [gsm], [LIBRARY_GSM="$LIBS";LIBS=""],
		   [AC_MSG_ERROR([libosmo-legacy-mgcp is built with transcoding and needs -lgsm but cannot find usable libgsm])])
    AC_SUBST(LIBRARY_GSM)
    if test "$osmo_ac_with_g729" = "yes" ; then
	PKG_CHECK_MODULES(LIBBCG729, libbcg729 >= 0.1, [AC_DEFINE([HAVE_BCG729], [1], [Use bgc729 decoder/encoder])])
    fi
fi

AC_DEFUN([CHECK_TM_INCLUDES_TM_GMTOFF], [
  AC_CACHE_CHECK(
    [whether struct tm has tm_gmtoff member],
    osmo_cv_tm_includes_tm_gmtoff,
    [AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
        #include <time.h>
      ], [
        time_t t = time(NULL);
        struct tm* lt = localtime(&t);
        int off = lt->tm_gmtoff;
      ])
    ],
    osmo_cv_tm_includes_tm_gmtoff=yes,
    osmo_cv_tm_includes_tm_gmtoff=no
    )]
  )
  if test "x$osmo_cv_tm_includes_tm_gmtoff" = xyes; then
    AC_DEFINE(HAVE_TM_GMTOFF_IN_TM, 1,
              [Define if struct tm has tm_gmtoff member.])
  fi
])

CHECK_TM_INCLUDES_TM_GMTOFF

AC_ARG_ENABLE([vty_tests],
		AC_HELP_STRING([--enable-vty-tests],
				[Include the VTY/CTRL tests in make check (deprecated)
				[default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install git://osmocom.org/python/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    openbsc.pc
    include/openbsc/Makefile
    include/Makefile
    src/Makefile
    src/libmsc/Makefile
    src/libvlr/Makefile
    src/libcommon/Makefile
    src/libcommon-cs/Makefile
    src/osmo-msc/Makefile
    src/utils/Makefile
    tests/Makefile
    tests/atlocal
    tests/smpp/Makefile
    tests/sms_queue/Makefile
    tests/msc_vlr/Makefile
    doc/Makefile
    doc/examples/Makefile
    contrib/Makefile
    Makefile)
