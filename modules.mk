#
# this is used/needed by the APACHE2 build system
#

MOD_ENCRYPT = mod_encrypt aes256ctr aes256cbc base64 crypt fcgi_buf fcgi_config fcgi_pm fcgi_protocol fcgi_util json key keythread memcache utctime log encap

mod_encrypt.la: ${MOD_ENCRYPT:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_ENCRYPT:=.lo} -lssl -lcrypto -ljansson -lcurl

DISTCLEAN_TARGETS = modules.mk

shared =  mod_encrypt.la

