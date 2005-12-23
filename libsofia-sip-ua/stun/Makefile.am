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
stun_lib_sources = 	stun.c stun_common.c
stun_prog_targets =     stunc torture_stun
else
stun_lib_targets = 
stun_prog_targets =
endif

noinst_LTLIBRARIES = 	libstun.la
noinst_PROGRAMS = 	${stun_prog_targets}

# ----------------------------------------------------------------------
# Rules for building the targets

include_sofia_HEADERS = stun.h stun_common.h stun_tag.h
libstun_la_SOURCES = 	$(stun_lib_sources) \
			stun_tag.c stun_tag_ref.c stun_internal.h

BUILT_SOURCES =		stun_tag_ref.c

COVERAGE_INPUT = 	$(libstun_la_SOURCES) $(include_sofia_HEADERS)

LDADD =			libstun.la \
			../su/libsu.la

torture_stun_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

# ----------------------------------------------------------------------
# Sofia specific rules
# XXX: torture_stun cannot be used as a automake test as is
#TESTS = 		torture_stun

include ../sofia.am

TAG_DLL_FLAGS =		LIST=stun_tag_list

built_sources: $(BUILT_SOURCES)
