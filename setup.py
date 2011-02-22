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
	# TODO: replace with check_output when python-2.7 is stable.
	output = subprocess.Popen(
		['git', 'describe'],
		stdout=subprocess.PIPE).communicate()[0]
	chunks = output.split('-')
	return '.'.join(chunks[:2])

def get_version():
	try:
		return get_version_from_file()
	except IOError:
		return get_version_from_git()

def get_option(args, name, default=False):
	disable_arg = "--disable-" + name
	enable_arg = "--enable-" + name
	if disable_arg in args and enable_arg in args:
		raise DistutilsArgError(
			"Conflicting flags: %s, %s" % (disable_arg, enable_arg))
	
	if disable_arg in args:
		args.remove(disable_arg)
		return False
	
	if enable_arg in args:
		args.remove(enable_arg)
		return True
	
	return default

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

scripts = ["scripts/v8-extract-version"]
data_files = []

cmdclass = {'sdist': my_sdist}

args = sys.argv[1:]

enable_subversion = get_option(args, 'subversion', default=True)
if enable_subversion:
	scripts += ["scripts/v8-create-tarball"]
	data_files += [["libexec", ["scripts/chromium-depot-tool"]]]
	cmdclass['install_data'] = my_install_data

setup(
	name="chromium-tools",
	version=get_version(),
	py_modules=["chromium_tools"],
	scripts=scripts,
	data_files=data_files,
	cmdclass=cmdclass,
	script_args=args
)
