#!/usr/bin/env python

from __future__ import print_function

import re
import sys
try:
  from urllib.request import urlopen
except ImportError:
  from urllib2 import urlopen

CVE_PATTERN = re.compile('CVE-\d{4}-\d+')


def main(argv):
  response = urlopen(argv[0])
  cves = set(CVE_PATTERN.findall(str(response.read())))
  print(','.join(cves))
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
