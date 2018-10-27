#!/bin/sh

PACKAGE=`pwd`
PACKAGE=`basename $PACKAGE`
VERSION=1.0-1
PKGDIR=${PACKAGE}_${VERSION}

if [ ! -f /usr/bin/automake ]; then
  echo "Error: no automake. Run: sudo apt-get install -y automake" 1>&2 
  exit 1
fi

if [ ! -f Makefile.in ]; then
  ./build_setup
  ./configure
fi
make
for dir in out deb
do
  mkdir -p $dir || exit 1
  cd $dir
done
mkdir -p $PKGDIR                || exit 1
mkdir -p $PKGDIR/DEBIAN         || exit 1
mkdir -p $PKGDIR/etc            || exit 1
mkdir -p $PKGDIR/etc/keepalived || exit 1
mkdir -p $PKGDIR/usr            || exit 1
mkdir -p $PKGDIR/usr/sbin       || exit 1
if [ ! -f $PKGDIR/usr/sbin/keepalived ]; then
  ln ../../bin/keepalived $PKGDIR/usr/sbin
fi
cat <<EOF > $PKGDIR/DEBIAN/control
Package: esi-keepalived
Version: $VERSION
Section: base
Priority: required
Architecture: amd64
Maintainer: NTT Innovation Institute, Inc. <support@ntti3.com>
Description: esi-keepalived
 Keepalived 2.0.7 modified for ESI
EOF
dpkg-deb --build $PKGDIR
