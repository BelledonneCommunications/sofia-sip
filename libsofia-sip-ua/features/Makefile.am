#
# Makefile.am for sofia features module
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
			-I$(srcdir)/../nua \
			-I$(srcdir)/../sdp \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../soa \
			-I$(srcdir)/../tport \
			-I$(srcdir)/../url \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsofia.la

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =       sofia_sip_features.h

libsofia_la_SOURCES = 	sofia_sip_features.c

# ----------------------------------------------------------------------
# Install and distribution rules

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am
