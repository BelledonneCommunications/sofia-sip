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

noinst_LIBRARIES = 	libiptsec.a

noinst_PROGRAMS = 	auth_digest_test iptsec_objs.o

TESTS = 		auth_digest_test

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES = 	auth_tag_ref.c

include_HEADERS =       auth_client.h auth_digest.h auth_dll.h \
			auth_module.h auth_plugin.h

libiptsec_a_SOURCES = 	iptsec_debug.h \
			auth_client.c auth_digest.c \
			auth_module.c auth_tag.c auth_tag_ref.c \
			auth_plugin.c auth_plugin_delayed.c \
			$(SIPSOURCES) $(HTTPSOURCES) \
			iptsec_debug.c

SIPSOURCES = 		auth_module_sip.c
HTTPSOURCES = 		auth_module_http.c 

iptsec_objs_o_SOURCES =	$(libiptsec_a_SOURCES)
iptsec_objs_o_LDADD =	

COVERAGE_INPUT = 	$(iptsec_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libiptsec.a \
			-L../ipt -lipt \
			-L../http -lhttp \
			-L../msg -lmsg \
			-L../nta -lnta \
			-L../sip -lsip \
			-L../url -lurl \
			-L../bnf -lbnf \
			-L../su -lsu

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST = 		Doxyfile iptsec.docs testpasswd \
			auth_module_sip.c auth_module_http.c $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
