#
# this is used/needed by the APACHE2 build system
#

MOD_ENCRYPT_SLO = mod_encrypt fcgi_pm fcgi_util fcgi_protocol fcgi_buf fcgi_config log memcache aes256cbc aes256ctr base64 crypt encap json key keythread utctime jansson/dump jansson/error jansson/hashtable jansson/hashtable_seed jansson/load jansson/memory jansson/pack_unpack jansson/strbuffer jansson/strconv jansson/utf jansson/value

MOD_ENCRYPT_LO = mod_encrypt fcgi_pm fcgi_util fcgi_protocol fcgi_buf fcgi_config log memcache aes256cbc aes256ctr base64 crypt encap json key keythread utctime dump error hashtable hashtable_seed load memory pack_unpack strbuffer strconv utf value

mod_encrypt.la: ${MOD_ENCRYPT_SLO:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_ENCRYPT_LO:=.lo} -lssl -lcrypto -lcurl

DISTCLEAN_TARGETS = modules.mk

shared =  mod_encrypt.la

