#!/bin/bash
# spdx-license-identifier: GPL-2.0-or-later
# Script to iterate over `ebuild foo-1.2.3.ebuild clean merge` and automatically add values to keeplibs.
# Usage: ./iterate-over-ebuild.sh foo-1.2.3.ebuild
# This script will run until the ebuild is merged, or until you interrupt it with Ctrl+C.
# It will add the libraries to keeplibs in the ebuild as it goes.

package="${1%.ebuild}"
tmpfile=$(mktemp)
iter=0
added=()
timeout_secs=300

# Trap for Ctrl+C
trap 'cleanup' INT

cleanup() {
  echo "[$(date)]: Script interrupted."
  echo "$tmpfile" for this iteration\'s logs.
  exit 1
}

while true; do
  start_time=$(date +%s)
  libs=()
  echo "[$(date)]: Processing $package; iteration $((++iter))"
  echo "So far, we've added:"
  if [ ${#added[@]} -eq 0 ]; then
    echo "  Nothing"
  fi
  for i in "${added[@]}"; do
    echo "  $i"
  done
  ebuild "${1}" clean merge 2>&1 | tee "$tmpfile"

  # Should only ever be one but whatever
  mapfile -t libs < <(grep 'ninja: error:' "$tmpfile" | awk '{print $3}' | cut -c 8- | awk -F/ '{OFS="/"; NF--; print}')

  if [ ${#libs[@]} -eq 0 ]; then
    echo "[$(date)]: No new libraries to whitelist."
  else
    for lib in "${libs[@]}"; do
      echo "[$(date)]: Whitelisting $lib"
      if grep -q "$lib$" "${1}"; then
        # Something went wrong if we're here but whatever.
        echo "[$(date)]: $lib already exists in keeplibs"
      else
        echo "[$(date)]: Adding $lib to keeplibs"
        sed -i "/^\s*local keeplibs=/a $lib" "${1}"
        added+=("$lib")
      fi
    done
  fi

  if grep -q "www-client/$package merged" "$tmpfile"; then
    rm "$tmpfile"
    break
  fi

  end_time=$(date +%s)
  elapsed_time=$((end_time - start_time))
  if [ $elapsed_time -gt $timeout_secs ]; then
    echo "[$(date)]: Ebuild execution took longer than the timeout. This is likely a build failure that requires patching. Exiting."
    echo "$tmpfile" for this iteration\'s logs.
    exit 1
  fi

  # Start with a clean slate for the next iteration
  rm "$tmpfile"
done
