SUBDIRS = \
	sms_queue \
	msc_vlr \
	$(NULL)

if BUILD_SMPP
SUBDIRS += \
	smpp \
	$(NULL)
endif

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	vty_test_runner.py \
	ctrl_test_runner.py \
	smpp_test_runner.py \
	test_nodes.vty \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
# don't run multiple tests concurrently so that the ports don't conflict
python-tests: $(BUILT_SOURCES)
	$(MAKE) vty-test
	$(MAKE) ctrl-test
if BUILD_SMPP
	$(MAKE) smpp-test
endif

else
python-tests: $(BUILT_SOURCES)
	echo "Not running python-based tests (determined at configure-time)"
endif

vty-python-test: $(BUILT_SOURCES)
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	$(srcdir)/vty_test_runner.py -w $(abs_top_builddir) -v
	rm -f $(top_builddir)/sms.db

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-transcript-test U=-u
vty-transcript-test:
	osmo_verify_transcript_vty.py -v \
		-n OsmoMSC -p 4254 \
		-r "$(top_builddir)/src/osmo-msc/osmo-msc -c $(top_srcdir)/doc/examples/osmo-msc/osmo-msc.cfg" \
		$(U) $${T:-$(srcdir)/*.vty}
	rm -f $(builddir)/sms.db

# don't run multiple tests concurrently so that the ports don't conflict
vty-test:
	$(MAKE) vty-python-test
	$(MAKE) vty-transcript-test

ctrl-python-test: $(BUILT_SOURCES)
	$(srcdir)/ctrl_test_runner.py -w $(abs_top_builddir) -v
	rm -f $(top_builddir)/sms.db

# To update the CTRL script from current application behavior,
# pass -u to ctrl_script_runner.py by doing:
#   make ctrl-transcript-test U=-u
ctrl-transcript-test:
	echo "No ctrl-transcript-test exists yet"

# don't run multiple tests concurrently so that the ports don't conflict
ctrl-test:
	$(MAKE) ctrl-python-test
	$(MAKE) ctrl-transcript-test

smpp-test:
	$(srcdir)/smpp_test_runner.py -w $(abs_top_builddir) -v
	rm -f $(top_builddir)/sms.db

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
