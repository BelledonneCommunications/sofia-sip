#
# Makefile.am @template@ for stun module
#

# ----------------------------------------------------------------------
# General options

AUTOMAKE_OPTIONS = 	foreign

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

if HAVE_TLS
stun_lib_targets = 	libstun.a
stun_prog_targets =	stun_objs.o stunc torture_stun
else
stun_lib_targets = 
stun_prog_targets =
endif

noinst_LIBRARIES = 	${stun_lib_targets}
noinst_PROGRAMS = 	${stun_prog_targets}

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS = 	stun.h stun_common.h

libstun_a_SOURCES = 	stun.c stun_common.c

stun_objs_o_SOURCES =	$(libstun_a_SOURCES)
stun_objs_o_LDADD =	

COVERAGE_INPUT = 	$(stun_objs_o_SOURCES) $(include_HEADERS)

# common LDFLAGS to all utils
LDADD =			libstun.a \
			-L../su -lsu

stunc_DEPENDENCIES = 	$(LIBDEP) libstun.a
stunc_SOURCES = 	stunc.c

torture_stun_DEPENDENCIES = $(LIBDEP) libstun.a
torture_stun_SOURCES = 	torture_stun.c

# ----------------------------------------------------------------------
# Install and distribution rules

# ----------------------------------------------------------------------
# Sofia specific rules
# XXX: torture_stun cannot be used as a automake test as is
#TESTS = 		torture_stun

include ../sofia.am

test: check
built_sources: $(BUILT_SOURCES)
libtarget: $(lib_LIBRARIES)

%.libtarget:
	$(MAKE) -C $(*) $(MFLAGS) libtarget SUBTARGETS=

doc:
	doxygen
