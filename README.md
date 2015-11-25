mod_encrypt
================

**mod_encrypt** is Apache module that add Data encryption into 
[mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).

Overview
--------

This module enables [mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html) 
to encrypt/decrypt data between client and FastCGI application.  
It support [mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html) entirely 
and add some features for data encrypt.

The encryption engine is AES CTR 256 from OpenSSL.

- **mod_encrypt** receive plaintext from client and encrypt it using the client-specific 
encryption key. This ciphertext is passed to FastCGI application.
- **mod_encrypt** receive ciphertext from FastCGI application and decrypt it 
using the client-specific encryption key. This plaintext is passed to client.

The encryption key is managed only by **mod_encrypt**.  
Client and FastCGI can not know about that at all.  
This is very effective to store client-specific data in the cloud storage using [mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).

How to Use It  
-------------

It support all the directives used by [mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).

This is the simple example how to use mod_encyrpt :

      LoadModule encrypt_module modules/mod_encrypt.so
      <IfModule encrypt_module>
          AddHandler encrypt-script .fcgi
          FastCgiEncExternalServer /var/www/html/myFCGI -host 192.168.0.1:3000
          FastCgiEncEncrypt On
          FastCgiEncDecrypt On
          FastCgiEncAuthServer 52.25.196.147
          FastCgiEncMasterKeyServer 52.25.196.147
          FastCgiEncDataKeyServer 52.25.196.147
          FastCgiEncKeyString testkeystring
          FastCgiEncMemcachedServer 127.0.0.1:11211
          FastCgiEncUserName test_user
          FastCgiEncPassword test_password
          FastCgiEncLogpath /var/log/httpd/encrypt.log 7
      </IfModule>

myFCGI and host IP/Port should be changed in your case.  
You can test it using curl.  
$ curl -v -XPUT http://localhost/myFCGI --data-binary teststring  

#### Directives for encyption
##### FastCgiEncEncrypt
Syntax: FastCgiEncEncrypt _On_ / _Off_  
Default: FastCgiEncEncrypt On  
Context: server config  

Enable / Disable the feature of FastCGI encrypt.  

##### FastCgiEncDecrypt
Syntax: FastCgiEncDecrypt _On_ / _Off_  
Default: FastCgiEncDecrypt On  
Context: server config  

Enable / Disable the feature of FastCGI decrypt.  

##### FastCgiEncAuthServer
Syntax: FastCgiEncAuthServer URL(IP address)  
Default: FastCgiEncAuthServer NONE  
Context: server config  

Config Authenticateion server name or IP address.  

##### FastCgiEncMasterKeyServer
Syntax: FastCgiEncMasterKeyServer URL(IP address)  
Default: FastCgiEncMasterKeyServer NONE  
Context: server config  

Config Master key server name or IP address.  

##### FastCgiEncDataKeyServer
Syntax: FastCgiEncDataKeyServer URL(IP address)  
Default: FastCgiEncDataKeyServer NONE  
Context: server config  

Config Data key server name or IP address.  

##### FastCgiEncKeyString
Syntax: FastCgiEncKeyString keystring  
Default: FastCgiEncKeyString NONE  
Context: server config  

Config Encryption/Decryption key string if key server is not set.  

#### Directives for memcached
##### FastCgiEncMemcachedServer
Syntax: FastCgiEncMemcachedServer hostname:port  
Default: FastCgiEncMemcachedServer 127.0.0.1:11211  
Context: server config  

Config Memcached server IP and port number.  

#### Directives for user authentication
##### FastCgiEncUserName, FastCgiEncPassword
Syntax: FastCgiEncUserName username, FastCgiEncPassword password  
Default: FastCgiEncUserName NONE, FastCgiEncPassword NONE  
Context: server config    
  
Config user name and password for user authentication of key store  

#### Directives for logging
##### FastCgiEncLogpath
Syntax: FastCgiEncLogpath filepath level 
Default: FastCgiEncLogpath NONE  
Context: server config    
  
Config log file path and level  
Need to set user RW permission to the file directory of log  
level EMERG:0, ALERT:1, CRIT:2, ERR:3, WARN:4, NOTICE:5, INFO:6, DEBUG:7  
