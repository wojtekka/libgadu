#!/bin/sh

# samba-winbind package is currently broken, what makes not possible to install
# wine. Zypper don't allow ignoring dependencies in non-interactive mode, so
# we need to fetch the package manually and install it with rpm tool.

set -e

export REPO="http://download.opensuse.org/tumbleweed/repo/oss/suse"

zypper in -y wget | tee /wget-deps
WGET_DEPS=`cat /wget-deps | grep -A 1 -e 'The following [0-9]\+ NEW packages' | tail -n 1`
rm /wget-deps
if [[ "$WGET_DEPS" != *"wget"* ]]; then
	echo "Can't retrieve wget deps"
	exit -1
fi

# fetch samba-winbind package name
wget "${REPO}/setup/descr/packages.gz"
gzip -d packages.gz
export SMB_PKG=`grep packages -e "samba-winbind-.*\.x86_64\.rpm" | grep -v "\-32bit\-" | sed -e "s/.*\(samba-.*rpm\).*/\1/"`

# download and install package
wget "${REPO}/x86_64/${SMB_PKG}" -O "${SMB_PKG}"
rpm -i --nodeps "${SMB_PKG}"

# cleanup
zypper rm -y ${WGET_DEPS}
rm "${SMB_PKG}"
rm packages
rm $0
