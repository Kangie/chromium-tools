#!/bin/bash
# This script fetches the libaom sources, checks out the appropriate tag
# and generates a tarball that can be placed in a devspace or other
# web-accessible site and added to SRC_URI for a given libaom release.
# Legacy manual instructions:
# To update test data tarball, follow these steps:
# 1.  Clone the upstream repo and check out the relevant tag,
#	  or download the release tarball
# 2.  Regular cmake configure (options don't matter here):
#     cd build && cmake ..
# 3.  Set LIBAOM_TEST_DATA_PATH to the directory you want and
#     run the "make testdata" target:
#     LIBAOM_TEST_DATA_PATH=../libaom-3.7.1-testdata make testdata
#     This will download the test data from the internet.
# 4.  Create a tarball out of that directory.
#     cd .. && tar cvaf libaom-3.7.1-testdata.tar.xz libaom-3.7.1-testdata

set -e

if [ -d /tmp/libaom ]; then
    rm -rf /tmp/libaom
fi

git clone https://aomedia.googlesource.com/aom /tmp/libaom

pushd /tmp/libaom
    # Assume we're getting the latest tag if not in env;
    # we're typically only packaging the latest version.
    LATEST_TAG="$(git tag --sort=taggerdate | tail -1)"
    TAG="${1:-$LATEST_TAG}"

    if [ -d "/tmp/libaom-${TAG:1}-testdata" ]; then
        rm -rf "/tmp/libaom-${TAG:1}-testdata"
    fi

    echo "Packaging libaom testdata for ${TAG}"
    git checkout "tags/${TAG}"

    cd build && cmake ..
    LIBAOM_TEST_DATA_PATH="/tmp/libaom-${TAG:1}-testdata" make -j$(nproc) testdata
popd
pushd /tmp
    XZ_OPT="-T0 -9" tar cvaf "libaom-${TAG:1}-testdata.tar.xz" "libaom-${TAG:1}-testdata"
popd

