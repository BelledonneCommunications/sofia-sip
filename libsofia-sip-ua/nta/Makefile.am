#
# Makefile.am for nta module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../ipt \
			-I$(srcdir)/../msg \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../sresolv \
			-I$(srcdir)/../tport \
			-I$(srcdir)/../url \
			-I$(srcdir)/../features \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnta.la

noinst_PROGRAMS = 	test_nta_api test_nta portbind
dist_noinst_SCRIPTS =	run_test_nta_api run_test_nta

TESTS =			run_test_nta_api run_test_nta
TESTS_ENVIRONMENT =	$(SHELL) 

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nta_tag_ref.c

include_sofia_HEADERS =       nta.h nta_stateless.h nta_tport.h \
			nta_tag.h nta_dll.h sl_utils.h 

libnta_la_SOURCES = 	nta.c nta_tag.c nta_tag_ref.c \
			nta_internal.h \
			sl_utils_print.c sl_utils_log.c \
			sl_read_payload.c

COVERAGE_INPUT = 	$(libnta_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libnta.la \
			../ipt/libipt.la \
			../sip/libsip.la \
			../features/libfeatures.la \
			../sresolv/libsresolv.la \
			../tport/libtport.la \
			../stun/libstun.la \
			../url/liburl.la \
			../msg/libmsg.la \
			../bnf/libbnf.la \
			../su/libsu.la

test_nta_LDFLAGS = 	-static

MOSTLYCLEANFILES +=	.test[0-9]*

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nta.docs sl_utils.docs \
			agent.pem cafile.pem \
			invite.msc $(BUILT_SOURCES) 

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
