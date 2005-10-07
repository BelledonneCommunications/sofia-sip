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

noinst_LIBRARIES = 	libnua.a

noinst_PROGRAMS =	nua_objs.o

noinst_PROGRAMS +=	test_nua

TESTS = 		test_nua

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nua_tag_ref.c

include_HEADERS =       nua.h nua_stack.h nua_tag.h

libnua_a_SOURCES = 	nua.c nua_common.c nua_stack.c \
			nua_tag.c nua_tag_ref.c

nua_objs_o_SOURCES =	$(libnua_a_SOURCES)
nua_objs_o_LDADD =	

COVERAGE_INPUT = 	$(nua_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libnua.a \
			-L../iptsec -liptsec \
			-L../ipt -lipt \
			-L../http -lhttp \
			-L../nea -lnea \
			-L../nta -lnta \
			-L../sresolv -lsresolv \
			-L../tport -ltport \
			-L../stun -lstun \
			-L../soa -lsoa \
			-L../sdp -lsdp \
			-L../sip -lsip \
			-L../msg -lmsg \
			-L../url -lurl \
			-L../bnf -lbnf \
			-L../su -lsu

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nua.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am

TAG_DLL_FLAGS =		LIST=nua_tag_list
