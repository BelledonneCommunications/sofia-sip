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
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnta.la

noinst_PROGRAMS = 	nta_test portbind 
dist_noinst_SCRIPTS =	run_nta_test

TESTS =			run_nta_test
TESTS_ENVIRONMENT =	$(SHELL) 

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nta_tag_ref.c

include_HEADERS =       nta.h nta_stateless.h nta_tport.h \
			nta_tag.h nta_dll.h sl_utils.h 

libnta_la_SOURCES = 	nta.c nta_tag.c nta_tag_ref.c \
			nta_internal.h \
			sl_utils.c sl_utils_print.c sl_utils_log.c \
			sl_read_payload.c

COVERAGE_INPUT = 	$(nta_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libnta.la \
			../ipt/libipt.la \
			../sip/libsip.la \
			../sresolv/libsresolv.la \
			../tport/libtport.la \
			../stun/libstun.la \
			../url/liburl.la \
			../msg/libmsg.la \
			../bnf/libbnf.la \
			../su/libsu.la

nta_test_SOURCES = 	nta_test.c

MOSTLYCLEANFILES +=	.test[0-9]*

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nta.docs sl_utils.docs \
			agent.pem cafile.pem \
			invite.msc $(BUILT_SOURCES) 

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

# Generate list of nta tags
TAG_DLL_FLAGS = 	LIST=nta_tag_list
