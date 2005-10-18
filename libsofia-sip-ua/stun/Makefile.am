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
stun_lib_targets = 	libstun.la
stun_prog_targets =     stunc torture_stun
else
stun_lib_targets = 
stun_prog_targets =
endif

noinst_LTLIBRARIES = 	${stun_lib_targets}
noinst_PROGRAMS = 	${stun_prog_targets}

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS = 	stun.h stun_common.h stun_tag.h

libstun_la_SOURCES = 	stun.c stun_common.c \
			stun_tag.c stun_tag_ref.c 

BUILT_SOURCES =		stun_tag_ref.c

COVERAGE_INPUT = 	$(libstun_la_SOURCES) $(include_HEADERS)

# common LDFLAGS to all utils
LDADD =			libstun.la \
			../su/libsu.la

stunc_DEPENDENCIES = 	$(LIBDEP) libstun.la
stunc_SOURCES = 	stunc.c

torture_stun_DEPENDENCIES = $(LIBDEP) libstun.la
torture_stun_SOURCES = 	torture_stun.c

# ----------------------------------------------------------------------
# Install and distribution rules

# ----------------------------------------------------------------------
# Sofia specific rules
# XXX: torture_stun cannot be used as a automake test as is
#TESTS = 		torture_stun

include ../sofia.am

TAG_DLL_FLAGS =		LIST=stun_tag_list

built_sources: $(BUILT_SOURCES)
