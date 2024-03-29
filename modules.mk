#
# this is used/needed by the APACHE2 build system
#

MOD_ENCRYPT_SLO = mod_encrypt fcgienc_pm fcgienc_util fcgienc_protocol fcgienc_buf fcgienc_config fcgienc_log fcgienc_aes256cbc fcgienc_aes256ctr fcgienc_base64 fcgienc_crypt fcgienc_encap fcgienc_json fcgienc_key fcgienc_memcache fcgienc_utctime jansson/dump jansson/error jansson/hashtable jansson/hashtable_seed jansson/load jansson/memory jansson/pack_unpack jansson/strbuffer jansson/strconv jansson/utf jansson/value

MOD_ENCRYPT_LO = mod_encrypt fcgienc_pm fcgienc_util fcgienc_protocol fcgienc_buf fcgienc_config fcgienc_log fcgienc_aes256cbc fcgienc_aes256ctr fcgienc_base64 fcgienc_crypt fcgienc_encap fcgienc_json fcgienc_key fcgienc_memcache fcgienc_utctime dump error hashtable hashtable_seed load memory pack_unpack strbuffer strconv utf value

KEY_PROCESS_SLO = fcgienc_aes256cbc fcgienc_aes256ctr fcgienc_base64 fcgienc_json fcgienc_keythread fcgienc_memcache fcgienc_utctime jansson/dump jansson/error jansson/hashtable jansson/hashtable_seed jansson/load jansson/memory jansson/pack_unpack jansson/strbuffer jansson/strconv jansson/utf jansson/value

KEY_PROCESS_LO = fcgienc_aes256cbc fcgienc_aes256ctr fcgienc_base64 fcgienc_json fcgienc_keythread fcgienc_memcache fcgienc_utctime dump error hashtable hashtable_seed load memory pack_unpack strbuffer strconv utf value

mod_encrypt.la: ${MOD_ENCRYPT_SLO:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_ENCRYPT_LO:=.lo} -lssl -lcrypto -lcurl

mod_enckeythread.bin: ${KEY_PROCESS_SLO:=.slo}
	$(BASE_CC) ${KEY_PROCESS_LO:=.o} -o mod_enckeythread.bin -lssl -lcrypto -lcurl -lapr-1 -laprutil-1


DISTCLEAN_TARGETS = modules.mk

shared =  mod_encrypt.la mod_enckeythread.bin

