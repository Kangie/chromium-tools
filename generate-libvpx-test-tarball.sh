#!/bin/bash
# This script fetches the libvpx sources, checks out the appropriate tag
# and generates a tarball that can be placed in a devspace or other
# web-accessible site and added to SRC_URI for a given libvpx release.
# Legacy manual instructions:
# To create a new testdata tarball:
# 1. Unpack source tarball or checkout git tag
# 2. mkdir libvpx-testdata
# 3. export LIBVPX_TEST_DATA_PATH=libvpx-testdata
# 4. ./configure --enable-unit-tests --enable-vp9-highbitdepth
# 5. make testdata
# 6. tar -caf libvpx-testdata-${MY_PV}.tar.xz libvpx-testdata

set -e

if [ -d /tmp/libvpx ]; then
    rm -rf /tmp/libvpx
fi

git clone https://github.com/webmproject/libvpx.git /tmp/libvpx

pushd /tmp/libvpx
    # Assume we're getting the latest tag if not in env;
    # we're typically only packaging the latest version.
    LATEST_TAG="$(git tag --sort=taggerdate | tail -1)"
    TAG="${1:-$LATEST_TAG}"

    if [ -d "/tmp/libvpx-${TAG:1}-testdata" ]; then
        rm -rf "/tmp/libvpx-${TAG:1}-testdata"
    fi

    mkdir -p "/tmp/libvpx-${TAG:1}-testdata"

    echo "Packaging libvpx testdata for ${TAG}"
    git checkout "tags/${TAG}"

    ./configure --enable-unit-tests --enable-vp9-highbitdepth
    LIBVPX_TEST_DATA_PATH="/tmp/libvpx-${TAG:1}-testdata" make -j$(nproc) testdata
popd
pushd /tmp
    XZ_OPT="-T0 -9" tar cvaf "libvpx-${TAG:1}-testdata.tar.xz" "libvpx-${TAG:1}-testdata"
popd
