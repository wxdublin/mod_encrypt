mod_encrypt-rpm
===============

**mod_encrypt** is Apache module that add Data encryption into 
[mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).


##Install##
1. sudo yum install mod_encrypt-1.0.0-1.x86_64.rpm

##Building##

1. yum install rpm-build rpmdevtools autoconf automake httpd httpd-devel apr-devel openssl-devel memcached libcurl-devel
2. yum groupinstall "Development Tools"
3. git clone https://github.com/GiorgioRegni/mod_encrypt.git
4. /usr/bin/rpmdev-setuptree
5. cp -f mod_encrypt/rpm/mod_encrypt.spec ~/rpmbuild/SPECS/
6. mv mod_encrypt mod_encrypt-1.0.0
7. tar -czvf ~/rpmbuild/SOURCES/mod_encrypt-1.0.0.tar.gz mod_encrypt-1.0.0
8. rpmbuild -bb ~/rpmbuild/SPECS/${whatami}.spec

RPM file is generated in ~/rpmbuild/RPMS/*/