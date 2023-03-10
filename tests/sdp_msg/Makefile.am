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
	sdp_msg_test.ok \
	sdp_msg_test.err \
	$(NULL)

check_PROGRAMS = \
	sdp_msg_test \
	$(NULL)

sdp_msg_test_SOURCES = \
	sdp_msg_test.c \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/sdp_msg_test >$(srcdir)/sdp_msg_test.ok 2>$(srcdir)/sdp_msg_test.err
