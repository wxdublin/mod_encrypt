mod_encrypt-rpm
===============

**mod_encrypt** is Apache module that add Data encryption into 
[mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).


##Install##
1. sudo yum install mod_encrypt-1.0.0-1.x86_64.rpm

##Building##

1. git clone https://github.com/GiorgioRegni/mod_encrypt.git
2. yum install rpm-build rpmdevtools autoconf automake httpd httpd-devel apr-devel openssl-devel memcached libcurl-devel
3. yum groupinstall "Development Tools"
4. ./build.sh mod_encrypt
5. sudo yum install ~/rpmbuild/RPMS/*/*.rpm

