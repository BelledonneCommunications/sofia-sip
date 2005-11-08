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

noinst_PROGRAMS =	test_tport

TESTS =			test_tport

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =	tport.h tport_tag.h

TLS_SRC =		tport_tls.c tport_tls.h

if HAVE_TLS
USE_TLS_SRC = 		$(TLS_SRC)
endif

libtport_la_SOURCES = 	tport.c tport_tag.c tport_tag_ref.c $(USE_TLS_SRC)

# to make sure all files end up in the dist package
EXTRA_DIST =	 	$(TLS_SRC)

BUILT_SOURCES =		tport_tag_ref.c

COVERAGE_INPUT = 	$(libtport_la_SOURCES) $(include_HEADERS)

LDADD = 		libtport.la \
			../stun/libstun.la \
			../ipt/libipt.la \
			../msg/libmsg_test.a ../msg/libmsg.la \
			../url/liburl.la \
			../bnf/libbnf.la \
			../su/libsu.la

test_tport_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST +=		Doxyfile tport.docs \
			certificates.html agent.pem cafile.pem

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
