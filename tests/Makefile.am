#
# Tests using check
#

EXTRA_DIST = check_sofia.h check_sofia.c suite_for_nua.c

TESTS =
tests_PROGRAMS =
testsdir := ${libdir}/tests/libsofia-sip-ua-tests

include $(top_srcdir)/rules/sofia.am

INCLUDES = ${INTERNAL_INCLUDES}

AM_CFLAGS += @CHECK_CFLAGS@

if HAVE_CHECK

TESTS += check2_sofia check_sofia 
tests_PROGRAMS += check2_sofia check_sofia

check2_sofia_SOURCES = \
	check2_sofia.c check2_sofia.h s2tester.h s2tester.c suite2_for_nua.c

check2_sofia_LDADD = \
	${sofiabuilddir}/libsofia-sip-ua.la \
	@CHECK_LIBS@

check_sofia_SOURCES = check_sofia.c check_sofia.h \
	suite_for_nua.c

NUA_TEST_LIBS := ${sofiabuilddir}/nua/libtestnua.la \
	${sofiabuilddir}/nua/libtestproxy.la \
	${sofiabuilddir}/nua/libtestnat.la

$(NUA_TEST_LIBS):
	cd ${sofiabuilddir}/nua && make checklib

check_sofia_LDADD = \
	$(NUA_TEST_LIBS) ${sofiabuilddir}/libsofia-sip-ua.la \
	@CHECK_LIBS@
endif
