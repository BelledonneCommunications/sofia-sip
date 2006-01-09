# ref: http://www.gnu.org/software/automake/manual/automake.html

# ----------------------------------------------------------------------
# Header paths

sofiasrc=$(top_srcdir)/libsofia-sip-ua

INCLUDES = 	-I$(sofiasrc)/features \
		-I$(sofiasrc)/ipt \
		-I$(sofiasrc)/iptsec \
		-I$(sofiasrc)/bnf \
		-I$(sofiasrc)/http \
		-I$(sofiasrc)/msg \
		-I$(sofiasrc)/nth \
		-I$(sofiasrc)/nta \
		-I$(sofiasrc)/nea \
		-I$(sofiasrc)/nua \
		-I$(sofiasrc)/soa \
		-I$(sofiasrc)/sdp \
		-I$(sofiasrc)/sip \
		-I$(sofiasrc)/soa \
		-I$(sofiasrc)/sresolv \
		-I$(sofiasrc)/tport \
		-I$(sofiasrc)/stun \
		-I$(sofiasrc)/url \
		-I$(sofiasrc)/su


# ----------------------------------------------------------------------
# Build targets

noinst_HEADERS = 	apps_utils.h

bin_PROGRAMS =		nua_cli sip-options sip-date

LDADD =			../libsofia-sip-ua/libsofia-sip-ua.la $(GLIB_LIBS)
