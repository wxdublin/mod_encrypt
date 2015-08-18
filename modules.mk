#
# this is used/needed by the APACHE2 build system
#

MOD_ENCRYPT = mod_encrypt fcgi_pm fcgi_util fcgi_protocol fcgi_buf fcgi_config crypt aes256 json memcache

mod_encrypt.la: ${MOD_ENCRYPT:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_ENCRYPT:=.lo} -lssl -lcrypto -ljansson

DISTCLEAN_TARGETS = modules.mk

shared =  mod_encrypt.la

