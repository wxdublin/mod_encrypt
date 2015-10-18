#
# this is used/needed by the APACHE2 build system
#

MOD_ENCRYPT = mod_encrypt fcgi_pm fcgi_util fcgi_protocol fcgi_buf fcgi_config log memcache aes256cbc aes256ctr base64 crypt encap json key keythread utctime

mod_encrypt.la: ${MOD_ENCRYPT:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_ENCRYPT:=.lo} -lssl -lcrypto -ljansson -lcurl

DISTCLEAN_TARGETS = modules.mk

shared =  mod_encrypt.la

