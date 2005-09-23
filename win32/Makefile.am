# ref: http://www.gnu.org/software/automake/manual/automake.html

# ----------------------------------------------------------------------

noinst_HEADERS = su_configure_win32.h unistd.h config.h

EXTRA_DIST = SofiaSIP.dsw \
	libsofia-sip-ua/libsofia_sip_ua.dsp \
	libsofia-sip-ua/sofia-sip-ua.def \
	nta_test/nta_test.dsp \
	$(NTV6_DIST) $(PTHREAD_DIST)

NTV6_DIST = \
	wspiapi.h \
	tpipv6.h \
	ntv6/include/ntddnapt.h \
	ntv6/include/ip6exp.h \
	ntv6/include/packon.h \
	ntv6/include/ipsec.h \
	ntv6/include/ntddip6.h \
	ntv6/include/ws2ip6.h \
	ntv6/include/ip6.h \
	ntv6/include/ntddtcp.h \
	ntv6/include/ipv6.h \
	ntv6/include/ip6addr.h \
	ntv6/include/tcp6info.h \
	ntv6/include/tdi.h \
	ntv6/include/packoff.h \
	ntv6/include/ws2tcpip-msr.h \
	ntv6/include/icmp6.h \
	ntv6/include/tcpinfo.h \
	ntv6/include/tdistat.h \
	ntv6/lib/wship6.lib

PTHREAD_DIST = \
	pthread/ChangeLog \
	pthread/pthread.dll \
	pthread/pthread.def \
	pthread/pthread.lib \
	pthread/semaphore.h \
	pthread/sched.h \
	pthread/md5.sum.txt \
	pthread/pthread.h

