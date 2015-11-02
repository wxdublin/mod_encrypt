#
# spec file for package mod_encrypt (Version 1.0.0)
#
# Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>

Name:           mod_encrypt
Version:        1.0.0
Release:        1

Group:          Web
License:        OpenSource

BuildRoot:      %{_tmppath}/%{name}-%{version}-build

Url:            http://www.github.com/GiorgioRegni/mod_encrypt/rpm
Source:         https://github.com/GiorgioRegni/mod_encrypt/rpm/%{name}-%{version}.tar.gz

Obsoletes: mod_encrypt <= %{version}-%{release}
Provides: mod_encrypt = %{version}-%{release}

BuildRequires: autoconf automake httpd httpd-devel apr-devel libcurl-devel openssl-devel
Requires: httpd apr libtool memcached 

Summary:        Encrypt module for Apache

%description
mod_encrypt is Apache module that add Data encryption into 
[mod_fastcgi](http://www.fastcgi.com/mod_fastcgi/docs/mod_fastcgi.html).

%prep
%setup -n %{name}-%{version}

%build
cp Makefile.AP2 Makefile
%{__make} top_dir="%{_libdir}/httpd"
%{__cat} << EOF > mod_encrypt.conf
# This is the Apache server configuration file for global fastcgi encrypt support.
# Some options can be overridden in the virtual host context.
# See <URL:https://github.com/GiorgioRegni/mod_encrypt/blob/master/README.md>

LoadModule encrypt_module modules/mod_encrypt.so

EOF


%install
%{__rm} -rf %{buildroot}
%{__make} install top_dir="%{_libdir}/httpd" DESTDIR="%{buildroot}"
%{__install} -Dp -m0644 mod_encrypt.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/encrypt.conf

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root, 0775)
%attr(0644,root,root) %{_libdir}/httpd/modules/%{name}.so
%attr(0644,root,root) %{_sysconfdir}/httpd/conf.d/encrypt.conf

