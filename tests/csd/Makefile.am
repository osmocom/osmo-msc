AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

EXTRA_DIST = \
	csd_test.ok \
	csd_test.err \
	$(NULL)

check_PROGRAMS = \
	csd_test \
	$(NULL)

csd_test_SOURCES = \
	csd_test.c \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/csd_test >$(srcdir)/csd_test.ok 2>$(srcdir)/csd_test.err
