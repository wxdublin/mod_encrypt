mod_encrypt-deb
===============

**mod_encrypt** is Apache module that add Data encryption into 
[mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).


##Install##
1. sudo dpkg -i libapache2-mod-encrypt_1.0.0-1_amd64.deb

##Building##

1. sudo apt-get install apache2 apache2-dev libcurl4-openssl-dev libtool dpkg-dev cdbs debhelper
2. git clone https://github.com/GiorgioRegni/mod_encrypt.git
3. cd mod_encrypt
4. dpkg-buildpackage -d -b

deb file is generated in ../