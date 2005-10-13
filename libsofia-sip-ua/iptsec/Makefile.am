#
# Makefile.am for iptsec module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../bnf \
	 		-I$(srcdir)/../ipt \
	 		-I$(srcdir)/../http \
			-I$(srcdir)/../msg \
			-I$(srcdir)/../nta \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../url \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libiptsec.la

noinst_PROGRAMS = 	auth_digest_test

TESTS = 		auth_digest_test

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES = 	auth_tag_ref.c

include_HEADERS =       auth_client.h auth_digest.h auth_dll.h \
			auth_module.h auth_plugin.h

libiptsec_la_SOURCES = 	iptsec_debug.h \
			auth_client.c auth_digest.c \
			auth_module.c auth_tag.c auth_tag_ref.c \
			auth_plugin.c auth_plugin_delayed.c \
			$(SIPSOURCES) $(HTTPSOURCES) \
			iptsec_debug.c

SIPSOURCES = 		auth_module_sip.c
HTTPSOURCES = 		auth_module_http.c 

COVERAGE_INPUT = 	$(libiptsec_la_SOURCES) $(include_HEADERS)

LDADD = 		libiptsec.la \
			../ipt/libipt.la \
			../http/libhttp.la \
			../msg/libmsg.la \
			../nta/libnta.la \
			../sip/libsip.la \
			../url/liburl.la \
			../bnf/libbnf.la \
			../su/libsu.la

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST = 		Doxyfile iptsec.docs testpasswd \
			auth_module_sip.c auth_module_http.c $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
