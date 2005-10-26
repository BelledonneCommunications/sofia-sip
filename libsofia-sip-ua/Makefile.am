# ref: http://www.gnu.org/software/automake/manual/automake.html

AUTOMAKE_OPTIONS = foreign

# note: order does matter in the subdir list
SUBDIRS = su bnf sresolv sdp url msg sip stun ipt soa \
	  tport http nea nta iptsec nth nua features
DIST_SUBDIRS = docs $(SUBDIRS)

EXTRA_DIST = sofia.am

lib_LTLIBRARIES = libsofia-sip-ua.la

if HAVE_TLS
tls_objs=stun/libstun.la
endif

libsofia_sip_ua_la_SOURCES = 
libsofia_sip_ua_la_LIBADD = 	bnf/libbnf.la \
				ipt/libipt.la \
				iptsec/libiptsec.la \
				msg/libmsg.la \
				nea/libnea.la \
				nta/libnta.la \
				nth/libnth.la \
				nua/libnua.la \
				http/libhttp.la \
				sdp/libsdp.la \
				sip/libsip.la \
				soa/libsoa.la \
				sresolv/libsresolv.la \
				su/libsu.la \
				tport/libtport.la \
				url/liburl.la \
				${tls_objs}

if ENABLE_COVERAGE
COVERAGE_RECURSIVE = coverage-recursive
coverage: $(COVERAGE_RECURSIVE)
endif

all-recursive: built-sources-recursive
built-sources: built-sources-recursive 
built-sources-recursive $(COVERAGE_RECURSIVE):
	target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  echo "Making $@ in $$subdir"; \
	  (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$target) \
	done;

empty-doxytags:
	@echo Generating empty doxytags ; \
	cd ${srcdir}; \
	for d in $(DIST_SUBDIRS); do \
	  test -r $$d/Doxyfile || continue ; \
	  test -d docs/$$d || mkdir docs/$$d ; \
	  test -r $$d/docs/doxytags || \
		echo '<?xml version="1.0"?>\
<tagfile />' >>  docs/$$d/doxytags ; \
	done

doxygen: built-sources empty-doxytags 
	@cd ${srcdir} ;\
	for d in $(DIST_SUBDIRS); do \
	  test -r ${srcdir}/$$d/Doxyfile \
	  && pushd $$d > /dev/null \
	  && echo running doxygen in $$d \
          && doxygen \
          && popd > /dev/null ; \
	done ; \
	cd ${srcdir}/docs/html && ../hide_emails.sh

.PHONY: built-sources built-sources-am empty-doxytags doxygen 
