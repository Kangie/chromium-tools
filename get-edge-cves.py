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

import dataclasses, datetime, sys
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup
from portage import versions as portage_versions
import requests


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


now = datetime.datetime.now()
year = now.year
month = now.strftime("%B")[0:3]

edge_cves = get_edge_cves(year, month)
for cve in edge_cves:
    print(cve)
