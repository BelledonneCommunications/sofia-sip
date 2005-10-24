#
# Makefile.am for nua module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../bnf \
	 		-I$(srcdir)/../ipt \
	 		-I$(srcdir)/../iptsec \
	 		-I$(srcdir)/../http \
			-I$(srcdir)/../msg \
			-I$(srcdir)/../nea \
			-I$(srcdir)/../nta \
			-I$(srcdir)/../nth \
			-I$(srcdir)/../sdp \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../soa \
			-I$(srcdir)/../tport \
			-I$(srcdir)/../url \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnua.la

noinst_PROGRAMS =	test_nua

TESTS = 		test_nua

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nua_tag_ref.c

include_HEADERS =       nua.h nua_stack.h nua_tag.h sofia_config.h

libnua_la_SOURCES = 	nua.c nua_common.c nua_stack.c \
			nua_tag.c nua_tag_ref.c \
			sofia_config.c

COVERAGE_INPUT = 	$(libnua_la_SOURCES) $(include_HEADERS)

LDADD = 		libnua.la \
			../iptsec/libiptsec.la \
			../ipt/libipt.la \
			../http/libhttp.la \
			../nea/libnea.la \
			../nta/libnta.la \
			../sresolv/libsresolv.la \
			../tport/libtport.la \
			../stun/libstun.la \
			../soa/libsoa.la \
			../sdp/libsdp.la \
			../sip/libsip.la \
			../msg/libmsg.la \
			../url/liburl.la \
			../bnf/libbnf.la \
			../su/libsu.la

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nua.docs $(BUILT_SOURCES) \
			sofia_config.h.in

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am

TAG_DLL_FLAGS =		LIST=nua_tag_list
