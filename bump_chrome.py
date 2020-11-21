#!/bin/env python3

import argparse
import json
import os
import shutil
import sys
import urllib.request

from portage.dbapi.porttree import portdbapi
from portage.versions import *
from portage.package.ebuild import digestgen, config
from portage.output import EOutput

from git import Repo

channels = ["stable", "beta", "dev"]
pkg_data = \
{
    "www-client" :
    {
        "stable" :
        {
            "pkg"     : "google-chrome",
            "suffix"  : None,
            "version" : None,
            "bump"    : False,
            "stable"  : False
        },
        "beta"   :
        {
            "pkg"     : "google-chrome-beta",
            "suffix"  : None,
            "version" : None,
            "bump"    : False,
            "stable"  : False
        },
        "dev"    :
        {
            "pkg"     : "google-chrome-unstable",
            "suffix"  : None,
            "version" : None,
            "bump"    : False,
            "stable"  : False
        }
    },
    "www-plugins" :
    {
        "stable" :
        {
            "pkg"     : "chrome-binary-plugins",
            "suffix"  : None,
            "version" : None,
            "bump"    : False,
            "stable"  : True
        },
        "beta" :
        {
            "pkg"     : "chrome-binary-plugins",
            "suffix"  : "beta",
            "version" : None,
            "bump"    : False,
            "stable"  : False
        },
        "dev"  :
        {
            "pkg"     : "chrome-binary-plugins",
            "suffix"  : "alpha",
            "version" : None,
            "bump"    : False,
            "stable"  : False
        }
    }
}

def getChromeVersionData(base_url, os):
    if not base_url.endswith("/"):
        url = base_url + "/"
    url += f"all.json?os={os}"

    response = urllib.request.urlopen(url)
    data = json.loads(response.read())
    return data[0]["versions"]

def getChromeChannelVersion(versions, channel):
    for item in versions:
        if item["channel"] == channel:
            return item["current_version"]
    return None

def isMajorBump(uversion, tversion):
    uv_list = uversion.split('.')
    tv_list = tversion.split('.')
    if int(uv_list[0]) > int(tv_list[0]):
        return True
    return False

def getPrevChannel(channel):
    channel_list = channels + [channels[len(channels) - 1]]
    for i in range(0, len(channel_list) - 1):
        if channel_list[i] == channel:
            return channel_list[i + 1]
    raise ValueError(f"Unknown channel \"{channel}\".")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit', '-c', action='store_true')
    parser.add_argument('--dry-run', '-n', action='store_true')
    args = parser.parse_args()

    output = EOutput()

    output.einfo("Fetching upstream version information ...")

    versions = getChromeVersionData(base_url="https://omahaproxy.appspot.com",
                                    os="linux")

    chrome_info = {}
    for channel in channels:
        chrome_info[channel] = None

    for channel in channels:
        chrome_info[channel] = getChromeChannelVersion(versions=versions,
                                                       channel=channel)

    output.einfo("Looking up Chrome version information in tree ...")

    db = portdbapi()
    repo_path = db.getRepositoryPath(repository_id="gentoo")
    for category in pkg_data.keys():
        for channel in channels:
            pkg  = pkg_data[category][channel]["pkg"]
            cpvs = db.cp_list(mycp=f"{category}/{pkg}", mytree=repo_path)
            pkg_data[category][channel]["version"] = None
            for cpv in cpvs:
                (cp, version, rev) = pkgsplit(mypkg=cpv)
                suffix = pkg_data[category][channel]['suffix']
                if suffix is not None:
                    suffix = "_" + suffix
                    if version.endswith(suffix):
                        pkg_data[category][channel]["version"] = version[:-len(suffix)]
                elif not "_" in version:
                    pkg_data[category][channel]["version"] = version
            if pkg_data[category][channel]["version"] is None:
                output.ewarn("Couldn't determine tree version for "+
                             "{category}/{pkg}")

    output.einfo("Comparing Chrome version informations ...")

    for channel in channels:
        if chrome_info[channel] is None:
            output.ewarn(f"Upstream version unknown for channel \"{channel}\".")
        else:
            for category in pkg_data.keys():
                pkg_data[category][channel]["bump"] = False
                ver_info = vercmp(chrome_info[channel],
                                  pkg_data[category][channel]["version"])
                if ver_info is None:
                    output.ewarn("Cannot determine new version for " +
                                 f"channel \"{channel}\" of " +
                                 f"{category}/" +
                                 f"{pkg_data[category][channel]['pkg']}.")
                elif ver_info > 0:
                    pkg_data[category][channel]["bump"] = True
                elif ver_info < 0:
                    output.ewarn("Upstream reverted bump for " +
                                 f"channel \"{channel}\" of " +
                                 f"{category}/" +
                                 f"{pkg_data[category][channel]['pkg']}.")

    for category in pkg_data.keys():
        for channel in channels:
            pkg = pkg_data[category][channel]["pkg"]
            output.einfo(f"{category}/{pkg} version information:")
            need_bump = pkg_data[category][channel]["bump"]
            uversion  = chrome_info[channel]
            tversion  = pkg_data[category][channel]["version"]
            output.einfo(f"\t{channel}\t{tversion}\t{uversion}" +
                         f"\t==> {'bump' if need_bump else 'no bump'}")

    repo = Repo(repo_path)
    if repo.is_dirty():
        output.eerror("Git Repository is dirty, can't continue.")
        sys.exit(1)

    index = repo.index
    for channel in channels:
        for category in pkg_data.keys():
            if not pkg_data[category][channel]["bump"]:
                continue
            uversion   = chrome_info[channel]
            tversion   = pkg_data[category][channel]["version"]
            major_bump = isMajorBump(uversion=uversion, tversion=tversion)
            pkg        = pkg_data[category][channel]["pkg"]
            suffix     = pkg_data[category][channel]["suffix"]
            if suffix is not None:
                suffix = "_" + suffix
            else:
                suffix = ""
            output.einfo(f"Bumping {category}/{pkg} ...")
            if major_bump:
                prev_channel = getPrevChannel(channel=channel)
                prev_pkg     = pkg_data[category][prev_channel]["pkg"]
                prev_version = pkg_data[category][prev_channel]["version"]
                prev_suffix  = pkg_data[category][prev_channel]["suffix"]
                print(prev_pkg)
                if prev_suffix is not None:
                    prev_suffix = "_" + prev_suffix
                else:
                    prev_suffix = ""
                from_ebuild = os.path.join(repo_path,
                                           category,
                                           prev_pkg,
                                           prev_pkg + "-" +
                                           prev_version + prev_suffix +
                                           ".ebuild")
            else:
                from_ebuild = os.path.join(repo_path,
                                           category,
                                           pkg,
                                           pkg + "-" +
                                           tversion + suffix +
                                           ".ebuild")
            to_ebuild = os.path.join(repo_path,
                                     category,
                                     pkg,
                                     pkg + "-" +
                                     uversion + suffix +
                                     ".ebuild")

            shutil.copyfile(from_ebuild, to_ebuild)

            index.add(to_ebuild)
            if major_bump:
                old_ebuild = os.path.join(repo_path,
                                          category,
                                          pkg,
                                          pkg + "-" +
                                          tversion + suffix +
                                          ".ebuild")
                index.remove(old_ebuild, working_tree=True)
            else:
                index.remove(from_ebuild, working_tree=True)

            to_path = os.path.dirname(to_ebuild)
            cfg = config.config()
            cfg["O"] = to_path

            digestgen.digestgen(None, cfg, db)

            index.add(os.path.join(to_path, "Manifest"))

            repo.git.commit("-m",
                            f"{category}/{pkg}: automated update ({uversion})",
                            "-s", "-S")

if __name__ == "__main__":
    main()
