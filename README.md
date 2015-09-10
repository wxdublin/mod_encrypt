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
          FastCgiExternalServer /var/www/html/myFCGI -host 192.168.0.1:3000 -masterkeyserver www.masterkeyserver.com -datakeyserver www.datakeyserver.com
          FastCgiEncrypt On
          FastCgiDecrypt On
	  FastCgiMemcachedServer 127.0.0.1:11211
	  FastCgiUserName test_user
	  FastCgiPassword test_password
      </IfModule>

myFCGI and host IP/Port should be changed in your case.  
You can test it using curl.  
$ curl -v -XPUT http://localhost/myFCGI --data-binary teststring  

#### Directives for encyption
##### FastCgiEncrypt
Syntax: FastCgiEncrypt _On_ / _Off_  
Default: FastCgiEncrypt On  
Context: server config  

Enable / Disable the feature of FastCGI encrypt.  
##### FastCgiDecrypt
Syntax: FastCgiDecrypt _On_ / _Off_  
Default: FastCgiDecrypt On  
Context: server config  

Enable / Disable the feature of FastCGI decrypt.  

#### Directives for memcached
##### FastCgiMemcachedServer
Syntax: FastCgiMemcachedServer hostname:port  
Default: FastCgiMemcachedServer 127.0.0.1:11211  
Context: server config  

Config Memcached server IP and port number.  

#### Directives for user authentication
##### FastCgiUserName, FastCgiPassword
Syntax: FastCgiUserName username, FastCgiPassword password  
Default: FastCgiUserName NONE, FastCgiPassword NONE  
Context: server config    
  
Config user name and password for user authentication of key store  

#### Directives for logging
##### FastCgiLogpath
Syntax: FastCgiLogpath filepath  
Default: FastCgiLogpath NONE  
Context: server config    
  
Config log file path  
Need to set user RW permission to the file directory of log  
