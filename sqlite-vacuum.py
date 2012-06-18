#!/usr/bin/env python

import os.path

import magic
import sqlite3

home = os.path.expanduser('~')

try:
	m = magic.open(magic.MAGIC_NONE)
	m.load()

	for root, dirs, files in os.walk(os.path.join(home, '.config', 'chromium')):
		for f in files:
			path = os.path.join(root, f)
			magic_type = m.file(path)
			if magic_type and 'SQLite' in magic_type:
				try:
					c = sqlite3.connect(path)
					c.execute('VACUUM')
					c.execute('REINDEX')
				finally:
					c.close()
finally:
	m.close()
