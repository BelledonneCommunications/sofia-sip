#
# Makefile.am for sofia-sip/packages
#
# Copyright (C) 2005,2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.

COND_PC_TARGETS =
if HAVE_GOBJECT
COND_PC_TARGETS += sofia-sip-ua-glib.pc
endif

# Install pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = sofia-sip-ua.pc $(COND_PC_TARGETS)

EXTRA_DIST = sofia-sip.spec sofia-sip.spec.in sofia-sip-ua.pc.in sofia-sip-ua-glib.pc.in

