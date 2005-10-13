#
# Makefile.am @template@ for su module
#

# ----------------------------------------------------------------------
# Headers

INCLUDES =		$(GLIB_CFLAGS)

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsu.la

bin_PROGRAMS = 		addrinfo localinfo 

noinst_PROGRAMS = 	su_torture torture_su_port \
			su_alloc_test su_time_test su_tag_test \
			htable_test torture_rbtree \
			test_memmem torture_su_memmem \
			su_root_test su_timer_test \
			su_test su_proxy poll_test

# ----------------------------------------------------------------------
# Tests

TESTS = 		su_torture torture_su_port \
			su_alloc_test su_time_test su_tag_test \
			htable_test torture_rbtree \
			test_memmem torture_su_memmem \
			su_root_test su_timer_test \
			run_addrinfo run_localinfo run_su_test

# ----------------------------------------------------------------------
# Rules for building the targets

if HAVE_GLIB
GHEADERS = su_source.h
GSOURCES = su_source.c
endif

BUILT_SOURCES = su_tag_ref.c

include_HEADERS = su_types.h su.h su_localinfo.h \
	su_wait.h $(GHEADERS) \
	su_alloc.h su_alloc_stat.h su_strlst.h su_vector.h \
	su_time.h \
	su_tag.h su_tag_class.h su_tagarg.h \
	su_tag_io.h su_tag_inline.h \
	htable.h htable2.h \
	su_debug.h su_module_debug.h su_log.h \
	su_config.h su_configure.h su_md5.h su_uniqueid.h \
	tstdef.h rbtree.h su_memmem.h

libsu_la_SOURCES = \
	su.c $(GSOURCES) \
	su_alloc.c su_alloc_lock.c su_strdup.c su_sprintf.c \
	su_strlst.c su_vector.c \
	su_time.c su_time0.c \
	su_wait.c su_root.c su_timer.c su_port.c su_port.h \
	su_localinfo.c \
	su_taglist.c su_tag.c su_tag_io.c \
	su_log.c su_global_log.c su_default_log.c \
	su_md5.c su_uniqueid.c su_memmem.c

COVERAGE_INPUT = 	$(su_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libsu.la $(GLIB_LIBS)

if NDEBUG
AM_CFLAGS = -DNDEBUG
endif

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST = 		Doxyfile su.docs \
			run_addrinfo run_localinfo run_su_test \
			memmem.c \
			su_tag_ref.c

dist_sofialibexec_SCRIPTS = tag_dll.awk

sofialibexecdir = $(libexecdir)/sofia

su_configure.h: su_configure.h.in

# ----------------------------------------------------------------------
# Automake options

AUTOMAKE_OPTIONS = 	foreign

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
