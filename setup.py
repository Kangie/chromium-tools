import os.path
import subprocess
import sys

from distutils.command.install_scripts import install_scripts
from distutils.command.install_data import install_data
from distutils.command.sdist import sdist
from distutils.core import setup
from distutils.errors import *

def get_version_from_file():
	return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VERSION')).read()

def get_version_from_git():
	output = subprocess.check_output(['git', 'describe'])
	chunks = output.split('-')
	return '.'.join(chunks[:2])

def get_version():
	try:
		return get_version_from_file()
	except IOError:
		return get_version_from_git()

class my_sdist(sdist):
	def make_release_tree(self, base_dir, files):
		sdist.make_release_tree(self, base_dir, files)
		open(os.path.join(base_dir, 'VERSION'), 'w').write(get_version_from_git())

class my_install_data(install_data):
	def run(self):
		install_data.run(self)
		for tool in ['drover', 'gcl', 'gclient']:
			os.symlink(
				os.path.join('..', 'libexec', 'chromium-depot-tool'),
				os.path.join(self.install_dir, 'bin', tool))

setup(
	name="chromium-tools",
	version=get_version(),
	scripts=["scripts/v8-create-tarball"],
	data_files=[["libexec", ["scripts/chromium-depot-tool"]]],
	cmdclass={'install_data': my_install_data, 'sdist': my_sdist},
)
