#!/bin/bash -e

MYPKG="chromium"
MYVERSION="99.0.4844.51"
#MYTARGETS=( "gcc_official" "gcc" "clang" "ozone" )
MYTARGETS=( "gcc" "clang" "ozone" )

MYRE2_SLOT="0/9"
MYICU_SLOT="0/70.1"

MYKEYWORD_PKGS=()
#MYKEYWORD_PKGS+=( "dev-util/gn" )
#MYKEYWORD_PKGS+=( "~media-video/ffmpeg-4.3.1" )
#MYKEYWORD_PKGS+=( "dev-libs/re2:${MYRE2_SLOT}" )
#MYKEYWORD_PKGS+=( "dev-libs/icu:${MYICU_SLOT}" )
#MYKEYWORD_PKGS+=( "=media-libs/libwebp-1.2.2" )

MYCATEGORY="www-client"
MYPKGDIR="$(portageq pkgdir)"
MYEBUILD="=${MYPKG}-${MYVERSION}"
MYEMERGE_OPTS="-vuDN --with-bdeps=y --complete-graph"
MYCCACHE_BASE="/var/tmp/ccache"
MYCCACHE_USE=true
MYUSE_FLAGS_BASE="-component-build -headless -custom-cflags cups hangouts js-type-check -kerberos pic proprietary-codecs pulseaudio suid -system-ffmpeg system-icu tcmalloc widevine"

MYTARGET_USE_gcc_official=( "${MYCATEGORY}/${MYPKG} -wayland -screencast vaapi official" )
MYTARGET_USE_gcc=( "${MYCATEGORY}/${MYPKG} -wayland -screencast -vaapi -official" )
MYTARGET_USE_clang=( "${MYCATEGORY}/${MYPKG} -wayland -screencast -vaapi -official" )
MYTARGET_USE_ozone=( "${MYCATEGORY}/${MYPKG} wayland screencast vaapi -official" )
MYTARGET_USE_ozone+=( "x11-libs/gtk+ wayland" )
MYTARGET_USE_ozone+=( "media-libs/mesa wayland" )

MYCOMPILERS_gcc_official=( "gcc-9.3.0" )
MYCOMPILERS_gcc=( "gcc-10.3.0" "gcc-11.2.0" )
MYCOMPILERS_clang=( "clang-13" )
MYCOMPILERS_ozone=( "gcc-11.2.0" )

# merge ccache
emerge ${MYEMERGE_OPTS} ccache
if [[ ! -d "${MYCCACHE_BASE}" ]]; then
	mkdir -p "${MYCCACHE_BASE}"
	chown root:portage "${MYCCACHE_BASE}"
	chmod 775 "${MYCCACHE_BASE}"
fi

# setup keywords
rm -f "/etc/portage/package.accept_keywords/chromium"
echo "=${MYCATEGORY}/${MYPKG}-${MYVERSION}" >> "/etc/portage/package.accept_keywords/chromium"

for mypkg in "${MYKEYWORD_PKGS[@]}"; do
	echo "$mypkg" >> "/etc/portage/package.accept_keywords/chromium"
done

# unmask chromium (dev channels are usually masked)
rm -f "/etc/portage/package.unmask/chromium"
echo "=${MYCATEGORY}/${MYPKG}-${MYVERSION}" >> "/etc/portage/package.unmask/chromium"

# setup base USE flags
echo "${MYCATEGORY}/${MYPKG} ${MYUSE_FLAGS_BASE}" > "/etc/portage/package.use/chromium-base"

for mytarget in "${MYTARGETS[@]}"; do

	# setup build USE flags
	mytarget_use="MYTARGET_USE_${mytarget}[@]"
	rm -f "/etc/portage/package.use/chromium-build"
	for myuse in "${!mytarget_use}"; do
		echo "${myuse}" >> "/etc/portage/package.use/chromium-build"
	done

	mycompilers="MYCOMPILERS_${mytarget}[@]"
	for mycompiler in "${!mycompilers}"; do
		mycc="x86_64-pc-linux-gnu-${mycompiler}"
		if [[ ${mycompiler} = gcc* ]]; then
			mycxx="x86_64-pc-linux-gnu-${mycompiler/gcc/g++}"
		else
			mycxx="x86_64-pc-linux-gnu-${mycompiler/clang/clang++}"
		fi
		rm -f "/etc/portage/env/chromium-cc.conf"
		echo "CC=\"${mycc}\"" >> "/etc/portage/env/chromium-cc.conf"
		echo "CXX=\"${mycxx}\"" >> "/etc/portage/env/chromium-cc.conf"
		myversion="${mycompiler#*-}"
		# remove installed package
		emerge --depclean -v "${MYCATEGORY}/${MYPKG}"

		mytargetdir="${mytarget}_${mycompiler%%-*}${myversion%%.*}"

		# setup ccache
		if [[ ! -d "${MYCCACHE_BASE}/${mytargetdir}" ]]; then
			mkdir "${MYCCACHE_BASE}/${mytargetdir}"
			chown root:portage "${MYCCACHE_BASE}/${mytargetdir}"
			chmod 775 "${MYCCACHE_BASE}/${mytargetdir}"
		fi
		if [[ ! -f "${MYCCACHE_BASE}/${mytargetdir}/ccache.conf" ]]; then
			cat <<- EOF > "${MYCCACHE_BASE}/${mytargetdir}/ccache.conf"
				max_size = 10.0G
				umask = 002
				compression = false
			EOF
			chown root:portage "${MYCCACHE_BASE}/${mytargetdir}/ccache.conf"
			chmod 664 "${MYCCACHE_BASE}/${mytargetdir}/ccache.conf"
		fi
		echo "CCACHE_DIR=\"${MYCCACHE_BASE}/${mytargetdir}\"" >> "/etc/portage/env/chromium-cc.conf"
		if [[ ${MYCCACHE_USE} = true ]]; then
			echo "FEATURES=\"ccache\"" >> "/etc/portage/env/chromium-cc.conf"
		fi

		# build chromium
		emerge ${MYEMERGE_OPTS} "${MYEBUILD}"
		# create binary package
#		PKGDIR="${MYPKGDIR}/${mytargetdir}" quickpkg ${MYPKG} --include-config=y
		# update access rights
		find "${MYPKGDIR}" -type d -exec chmod 755 {} \;
		find "${MYPKGDIR}" -type f -exec chmod 644 {} \;
	done
done
