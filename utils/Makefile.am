# ref: http://www.gnu.org/software/automake/manual/automake.html

# ----------------------------------------------------------------------
# Header paths

sofiasrc=$(top_srcdir)/libsofia-sip-ua

INCLUDES = 	-I$(sofiasrc)/ipt \
		-I$(sofiasrc)/iptsec \
		-I$(sofiasrc)/msg \
		-I$(sofiasrc)/nta \
		-I$(sofiasrc)/nua \
		-I$(sofiasrc)/sdp \
		-I$(sofiasrc)/sip \
		-I$(sofiasrc)/sresolv \
		-I$(sofiasrc)/tport \
		-I$(sofiasrc)/url \
		-I$(sofiasrc)/su


# ----------------------------------------------------------------------
# Build targets

include_HEADERS = 	apps_utils.h

bin_PROGRAMS =		nua_cli options sip_date

LDADD =			-L../libsofia-sip-ua -lsofia-sip-ua $(GLIB_LIBS)
