#!/bin/sh

# samba-winbind package is currently broken, what makes not possible to install
# wine. Zypper don't allow ignoring dependencies in non-interactive mode, so
# we need to fetch the package manually and install it with rpm tool.

set -e

export REPO="http://download.opensuse.org/tumbleweed/repo/oss/suse"

zypper in -y wget

# fetch samba-winbind package name
wget "${REPO}/setup/descr/packages.gz"
gzip -d packages.gz
export SMB_PKG=`grep packages -e "samba-winbind-.*\.x86_64\.rpm" | grep -v "\-32bit\-" | sed -e "s/.*\(samba-.*rpm\).*/\1/"`

# download and install package
wget "${REPO}/x86_64/${SMB_PKG}" -O "${SMB_PKG}"
rpm -i --nodeps "${SMB_PKG}"

# cleanup
zypper rm -y libicu56_1 libicu56_1-ledata libmetalink3 libpsl5 timezone wget
rm "${SMB_PKG}"
rm packages
rm $0
