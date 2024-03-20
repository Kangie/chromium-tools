#!/bin/bash

# This script actually only creates an appropriately-versioned GN tarball to assist
# in the process of bumping the GN version. It does not actually bump the GN version
# in the gentoo tree as we need to upload the tarball to a devspace.

# Users should set the following to make xz work:
# git config --global tar.tar.xz.command "xz -T0 -9 -c"

# check if /tmp/gn exists and if so delete it
if [ -d /tmp/gn ]; then
  rm -rf /tmp/gn
fi

# Clone the gn repo
git clone https://gn.googlesource.com/gn /tmp/gn

pushd /tmp/gn

commit=$(git describe --tags)
pattern="([^-]*)-([^-]*)-([^-]*)-(.*)"
[[ $commit =~ $pattern ]]
count="${BASH_REMATCH[3]}"

git archive --format=tar.xz --prefix=gn-0.${count}/ -o /tmp/gn-0.${count}.tar.xz HEAD

popd

echo "Tarball created at /tmp/gn-0.${count}.tar.xz"
