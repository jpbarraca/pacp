#!/bin/sh
#
# Run this to generate all the initial makefiles.
#

DIE=true
PROJECT="pacp"

# If you are going to use the non-default name for automake becase your OS
# installaion has multiple versions, you need to call both aclocal and automake
# with that version number, as they come from the same package.
AM_VERSION='1.7'

ACLOCAL=aclocal-$AM_VERSION
AUTOHEADER=autoheader-2.5x
AUTOMAKE=automake-$AM_VERSION
AUTOCONF=autoconf-2.5x

ACVER=`$AUTOCONF --version | grep '^autoconf' | sed 's/.*) *//'`
case "$ACVER" in
'' | 0.* | 1.* | 2.[0-4]* | \
2.5[0-1] | 2.5[0-1][a-z]* )
  cat >&2 <<_EOF_

	You must have autoconf 2.52 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/autoconf/
_EOF_
  DIE="exit 1"
  ;;
esac


AMVER=`$AUTOMAKE --version | grep '^automake' | sed 's/.*) *//' | cut -c 1,2,3`
case "$AMVER" in
'' | 0.* |1.[0-6] )

  cat >&2 <<_EOF_

	You must have automake $AM_VERSION (found $AMVER) or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/automake/
_EOF_
  DIE="exit 1"
	;;
esac

#
# Apple's Developer Tools have a "libtool" that has nothing to do with
# the GNU libtool; they call the latter "glibtool".  They also call
# libtoolize "glibtoolize".
#
# Check for "glibtool" first.
#
LTVER=`glibtool --version 2>/dev/null | grep ' libtool)' | \
    sed 's/.*libtool) \([0-9][0-9.]*\)[^ ]* .*/\1/'`
if test -z "$LTVER"
then
	LTVER=`libtool --version | grep ' libtool)' | \
	    sed 's/.*) \([0-9][0-9.]*\)[^ ]* .*/\1/' `
	LIBTOOLIZE=libtoolize
else
	LIBTOOLIZE=glibtoolize
fi
case "$LTVER" in
'' | 0.* | 1.[0-3]* )

  cat >&2 <<_EOF_

	You must have libtool 1.4 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/libtool/
_EOF_
  DIE="exit 1"
  ;;
esac

$DIE

echo "Running $ACLOCAL..."
$ACLOCAL
echo "Running $AUTOCONF..."
$AUTOCONF
echo "Running $AUTOMAKE..."
$AUTOMAKE
#./configure "$@" || exit 1

echo
echo "Now type \"./configure [options]\" and \"make\" to compile $PROJECT."
