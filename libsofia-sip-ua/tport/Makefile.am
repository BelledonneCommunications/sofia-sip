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

noinst_LIBRARIES = 	libtport.a

bin_PROGRAMS = 		

noinst_PROGRAMS =	tport_test tport_objs.o

TESTS =			tport_test $(TLS_TEST)

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =	tport.h tport_tag.h

if HAVE_TLS
TLS_SRC =		tport_tls.c tport_tls.h
endif

libtport_a_SOURCES = 	tport.c tport_tag.c tport_tag_ref.c $(TLS_SRC)

# to make sure all files end up in the dist package
EXTRA_DIST =	 	$(libtport_a_SOURCES) tport_tls.c tport_tls.h tport_test.c

BUILT_SOURCES =		tport_tag_ref.c

tport_objs_o_SOURCES =	$(libtport_a_SOURCES)
tport_objs_o_LDADD =	

LDADD = 		libtport.a \
			-L../stun -lstun \
			-L../ipt -lipt \
			-L../msg -lmsg \
			-L../url -lurl \
			-L../bnf -lbnf \
			-L../su -lsu 

tport_test_SOURCES = 	tport_test.c $(MSG_TEST_CLASS)

m = ${srcdir}/../msg

MSG_TEST_CLASS = $m/msg_test_class.c $m/msg_test_table.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST +=		Doxyfile tport.docs \
			certificates.html agent.pem cafile.pem

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am
