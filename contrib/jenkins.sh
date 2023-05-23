#!/usr/bin/env bash
# jenkins build helper script for openbsc.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * IU: configure 3G support (values: "--enable-iu", "--disable-iu")
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
# * IS_MASTER_BUILD: set to 1 when running from master-builds (not gerrit-verifications)
#

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi

exit_tar_workspace() {
	cat-testlogs.sh

	if [ "$IS_MASTER_BUILD" = "1" ]; then
		tar -cJf "/tmp/workspace.tar.xz" "$base"
		mv /tmp/workspace.tar.xz "$base"
	fi

	exit 1
}

set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

osmo-build-dep.sh libosmocore "" ac_cv_path_DOXYGEN=false

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif
osmo-build-dep.sh libosmo-sccp
osmo-build-dep.sh libsmpp34
osmo-build-dep.sh osmo-mgw
osmo-build-dep.sh osmo-hlr

if [ "x$IU" = "x--enable-iu" ]; then
	osmo-build-dep.sh libasn1c
	#osmo-build-dep.sh asn1c aper-prefix # only needed for make regen in osmo-iuh
	osmo-build-dep.sh osmo-iuh
fi

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== osmo-msc ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-werror --enable-smpp $IU --enable-external-tests $CONFIG
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || exit_tar_workspace
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="--enable-werror --enable-smpp $IU --enable-external-tests $CONFIG" \
  $MAKE $PARALLEL_MAKE distcheck \
  || exit_tar_workspace

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE $PARALLEL_MAKE maintainer-clean
osmo-clean-workspace.sh
