#!/bin/sh

whatami="$1"
whereami="$(dirname $0)"

/usr/bin/rpmdev-setuptree

cp -f ${whereami}/rpm/${whatami}.spec ~/rpmbuild/SPECS/
cp -f ${whereami}/rpm/${whatami}-1.0.0.tar.gz ~/rpmbuild/SOURCES/

rpmbuild -bb ~/rpmbuild/SPECS/${whatami}.spec 
