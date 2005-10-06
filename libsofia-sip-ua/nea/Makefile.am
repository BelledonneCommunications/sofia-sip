#
# Makefile.am for nea module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../ipt \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../nta \
		-I$(srcdir)/../sip \
		-I$(srcdir)/../sresolv \
		-I$(srcdir)/../tport \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	libnea.a

noinst_PROGRAMS = 	nea_objs.o

TESTS = 

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nea_tag_ref.c

include_HEADERS =       nea.h nea_dll.h nea_debug.h

libnea_a_SOURCES = 	nea.c nea_event.c \
			nea_server.c nea_debug.c nea_tag.c nea_tag_ref.c

nea_objs_o_SOURCES =	$(libnea_a_SOURCES)
nea_objs_o_LDADD =	

COVERAGE_INPUT = 	$(nea_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libnea.a \
			-L../nta -lnta \
			-L../ipt -lipt \
			-L../sip -lsip \
			-L../sresolv -lsresolv \
			-L../tport -ltport \
			-L../stun -lstun \
			-L../url -lurl \
			-L../msg -lmsg \
			-L../bnf -lbnf \
			-L../su -lsu 

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nea.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
