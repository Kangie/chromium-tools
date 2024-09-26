#!/usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-or-later
# This script extracts the Chromium version mapping for Microsoft Edge based on a given CVE ID.
# It uses the Microsoft Security Response Center (MSRC) API to get the Common Vulnerability Reporting Framework (CVRF)
# for a given month and extracts the Chromium version mapping for Microsoft Edge (Chromium-based) from the CVRF.

# API Docs https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json

# We can use the CVRF API to get the Common Vulnerability Reporting Framework (CVRF) for a given month.
# We can query the API via CVE ID to get the CVRF for a specific CVE, but that just leads us back to querying
# the month. Stretch goal to ingest directly from bgo ticket aliases and confirm the month & version?
# https://api.msrc.microsoft.com/cvrf/v3.0/updates/CVE-2024-7969

# https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug
# is the URL for the CVRF for August 2024

# The XML looks like this:
# <cvrfdoc
#  . . .
# <vuln:Vulnerability
#     Ordinal="261">
#     <vuln:Title>Chromium: CVE-2024-7969 Type Confusion in V8</vuln:Title>
#     . . .
#     <vuln:ProductStatuses>
#       <vuln:Status
#         Type="Known Affected">
#         <vuln:ProductID>11655</vuln:ProductID>
#         . . .
#     </vuln:ProductStatuses>
#     . . .
#     <vuln:CVE>CVE-2024-7969</vuln:CVE>
#     . . .
#     <vuln:Remediations>
#       <vuln:Remediation
#         Type="Vendor Fix">
#         <vuln:Description>Release Notes</vuln:Description>
#         <vuln:URL />
#         <vuln:ProductID>11655</vuln:ProductID>
#         <vuln:AffectedFiles />
#         <vuln:RestartRequired>No</vuln:RestartRequired>
#         <vuln:SubType>Security Update</vuln:SubType>
#         <vuln:FixedBuild>128.0.2739.42</vuln:FixedBuild>
#         . . .
#     </vuln:Remediations>
#     . . .
# </vuln:Vulnerability>

# Process: Pick a month, get the CVRF for that month, then iterate over vulnerabilities to find the ones
# that are for Microsoft Edge (Chromium-based) `<vuln:ProductID>11655</vuln:ProductID>`.
# Extract the <vuln:CVE>CVE-2024-7969</vuln:CVE> to extract a CVE ID and
# map to Chromium versions using the <vuln:FixedBuild>128.0.2739.42</vuln:FixedBuild> tag (or the notes if we _have_ to).

import argparse, calendar, dataclasses, datetime, os, sys
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup
from portage import versions as portage_versions
import bugzilla, requests


@dataclasses.dataclass
class EdgeCVE:
    cve: str
    title: str
    fixedbuild: str | None

    def __str__(self):
        return f"{self.cve}: {self.title}: Fixed {self.fixedbuild if not None else 'unknown'}"


def get_edge_cves(year, month) -> list[EdgeCVE]:
    msrcapi = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{year}-{month}"

    # Get the CVRF for the specified month
    response = requests.get(msrcapi)

    if response.status_code != 200:
        print(f"Website returned {response.status_code}")
        print(f"Failed to get CVRF for {year}-{month}")
        sys.exit(1)

    # Parse the XML
    root = ET.fromstring(response.text)

    # Find all the vulnerabilities
    vulnerabilities = root.findall(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability")

    edge_cves = []  # Store the edge cves here
    for vulnerability in vulnerabilities:
        productstatuses = vulnerability.findall(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}ProductStatuses")
        for productstatus in productstatuses:
            productid = productstatus.find(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}ProductID")
            if productid.text == "11655":
                # This is a Microsoft Edge (Chromium-based) vulnerability
                cve_id = vulnerability.find(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}CVE").text
                cve_title = vulnerability.find(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Title").text
                remediations = vulnerability.findall(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Remediations")
                for remediation in remediations:
                    fixedbuild = remediation.find(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}FixedBuild")
                    if fixedbuild is not None:
                        edge_cves.append(
                            EdgeCVE(cve_id, cve_title, fixedbuild.text)
                        )
                    else:
                        # Fall back to parsing that horrible, horrible table in the notes
                        notes = vulnerability.find(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Notes")
                        # There appear to be multiple notes, but only one has content that we want:
                        # <vuln:Note Title="FAQ" Type="FAQ" Ordinal="10">&lt;p&gt;&lt;strong&gt;What is the version information for this release?&lt;/strong&gt;&lt;/p&gt;
                        found = False
                        for note in notes:
                            if note.attrib['Title'] == "FAQ" and note.attrib['Type'] == "FAQ":

                                # The note contains a table with the chromium and edge versions, written in "HTML"
                                # &lt;td&gt;8/22/2024&lt;/td&gt;
                                content = note.text

                                soup = BeautifulSoup(content, 'html.parser')
                                rows = soup.find_all('tr')
                                # We want the second row, second cell
                                if len(rows) > 1:
                                    cells = rows[1].find_all('td')
                                    if len(cells) > 1:
                                        # We want the second cell (The first is the channel, the third the chromium version it's based on)
                                        edge_version = cells[1].text
                                        if portage_versions.ververify(edge_version):
                                            found = True
                                            edge_cves.append(
                                                EdgeCVE(cve_id, cve_title, edge_version)
                                            )

                        if not found:
                            edge_cves.append(
                                EdgeCVE(cve_id, cve_title, None)
                            )

    return edge_cves


def get_cve_from_bug_alias(bugnumber: int) -> list[str]:
    """
    Queries the Gentoo bugzilla instance for the list of CVEs associated with a given bug.

    Since we, by convention, alias bugs to CVEs, we can just query the alias field.

    Args:
        bugnumber (int): The bug number to query.

    Returns:
        list[str]: A list of CVEs associated with the bug.s

    """
    url = "bugs.gentoo.org"
    keyfile = open(os.path.abspath('./bugzilla_api_key'))
    api_key = keyfile.read().replace('\n','')
    print('connecting to b.g.o')
    bzapi = bugzilla.Bugzilla(url, api_key)
    bug = bzapi.getbug(bugnumber)
    cves = bug.alias
    print(f'Bug: {bug} has {len(cves)} CVEs.')

    return cves


def get_msrc_for_cve(cve: str) -> str:
    """
    Do a simple webrquest to get the CVRF for a given CVE.

    Args:
        cve (str): The CVE to query.

    Returns:
        str: The CVRF for the CVE.
    """

    msrcapi = f"https://api.msrc.microsoft.com/cvrf/v3.0/updates/{cve}"
    response = requests.get(msrcapi)

    if response.status_code != 200:
        print(f"Website returned {response.status_code}")
        print(f"Failed to get CVRF for {cve}")
        sys.exit(1)

    # This is JSON, we want { "value": [ { "ID": "2024-Aug" }, ] }
    return response.json().get('value')[0].get('ID')


def parse_arguments():
    parser = argparse.ArgumentParser(description="Script to get Edge CVEs.")
    parser.add_argument('-m', '--month', type=int, help='Month as a number (1-12)', default=datetime.datetime.now().month)
    parser.add_argument('-y', '--year', type=int, help='Year as a four-digit number', default=datetime.datetime.now().year)
    parser.add_argument('-b', '--bug', nargs='*', help='List of bug identifiers')
    parser.add_argument('-c', '--cve', nargs='*', help='List of CVE identifiers')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.bug and not args.cve:
        month = calendar.month_name[args.month][0:3]
        for cve in get_edge_cves(args.year, month):
            print(cve)

    elif args.bug:
        for bug in args.bug:
            cves = get_cve_from_bug_alias(bug)

            msrcs = []
            for cve in cves:
                msrcs.append(get_msrc_for_cve(cve))

            # Dedupe
            msrcs = list(set(msrcs))

            for msrc in msrcs:
                for cve in get_edge_cves(msrc.split('-')[0], msrc.split('-')[1]):
                    if cve.cve in cves:
                        print(cve)

    elif args.cve:
        msrcs = []
        cves = []
        for cve_id in args.cve:
            cves.append(cve_id)
            msrcs.append(get_msrc_for_cve(cve_id))

        # Dedupe
        msrcs = list(set(msrcs))

        for msrc in msrcs:
            for cve in get_edge_cves(msrc.split('-')[0], msrc.split('-')[1]):
                if cve.cve in cves:
                    print(cve)


if __name__ == "__main__":
    main()
