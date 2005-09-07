#
# Makefile.am for nth module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../ipt \
		-I$(srcdir)/../iptsec \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../http \
		-I$(srcdir)/../sresolv \
		-I$(srcdir)/../tport \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	libnth.a

noinst_PROGRAMS = 	nth_test http-client http-server nth_objs.o

TESTS = 		nth_test

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nth_tag_ref.c

include_HEADERS =       nth.h nth_tag.h

libnth_a_SOURCES = 	nth_client.c nth_server.c nth_tag.c nth_tag_ref.c

nth_objs_o_SOURCES =	$(libnth_a_SOURCES)
nth_objs_o_LDADD =	
nth_objs_o_LDFLAGS =

LDADD = 		libnth.a \
			-L../iptsec -liptsec \
			-L../ipt -lipt \
			-L../http -lhttp \
			-L../sresolv -lsresolv \
			-L../tport -ltport \
			-L../stun -lstun \
			-L../url -lurl \
			-L../msg -lmsg \
			-L../bnf -lbnf \
			-L../su -lsu 


# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nth.docs $(BUILT_SOURCES) \
			agent.pem cafile.pem

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
