#!/usr/bin/env python

from __future__ import print_function

import re
import sys
try:
  from urllib.request import urlopen
except ImportError:
  from urllib2 import urlopen

CVE_PATTERN = re.compile('CVE-(\d{4})-(\d+)')


def main(argv):
  response = urlopen(argv[0])
  cves = CVE_PATTERN.findall(str(response.read()))
  years = {}
  for year, no in cves:
    if year not in years:
      years[year] = []
    years[year].append(no)
  result = []
  for year in sorted(years.keys()):
    nos = years[year]
    if len(nos) == 1:
      result.append('CVE-%s-%s' % (year, nos[0]))
    else:
      result.append('CVE-%s-{%s}' % (year, ','.join(sorted(nos))))
  print(' '.join(result))
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
