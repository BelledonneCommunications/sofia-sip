#
# Makefile.am @template@ for tport module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../bnf \
			-I$(srcdir)/../stun \
			-I$(srcdir)/../ipt \
			-I$(srcdir)/../msg \
			-I$(srcdir)/../url \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libtport.la

bin_PROGRAMS = 		

noinst_PROGRAMS =	tport_test

TESTS =			tport_test

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =	tport.h tport_tag.h

if HAVE_TLS
TLS_SRC =		tport_tls.c tport_tls.h
endif

libtport_la_SOURCES = 	tport.c tport_tag.c tport_tag_ref.c $(TLS_SRC)

# to make sure all files end up in the dist package
EXTRA_DIST =	 	$(libtport_a_SOURCES) tport_tls.c tport_tls.h tport_test.c

BUILT_SOURCES =		tport_tag_ref.c

COVERAGE_INPUT = 	$(libtport_la_SOURCES) $(include_HEADERS)
COVERAGE_INPUT = 	$(libtport_la_SOURCES) $(include_HEADERS)

LDADD = 		libtport.la \
			../stun/libstun.la \
			../ipt/libipt.la \
			../msg/libmsg_test.a ../msg/libmsg.la \
			../url/liburl.la \
			../bnf/libbnf.la \
			../su/libsu.la

tport_test_SOURCES = 	tport_test.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST +=		Doxyfile tport.docs \
			certificates.html agent.pem cafile.pem

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am
