import os.path
import subprocess

from distutils.command.install_scripts import install_scripts
from distutils.command.sdist import sdist
from distutils.core import setup

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

class my_sdist(sdist):
	def make_release_tree(self, base_dir, files):
		sdist.make_release_tree(self, base_dir, files)
		open(os.path.join(base_dir, 'VERSION'), 'w').write(get_version_from_git())

class my_install_scripts(install_scripts):
	def __symlink(self, src, dst):
		dest_name, _ = self.copy_file(
			src,
			os.path.join(self.install_dir, dst),
			link='sym')
		self.outfiles.append(dest_name)

	def run(self):
		install_scripts.run(self)
		self.__symlink('chromium-depot-tool', 'drover')
		self.__symlink('chromium-depot-tool', 'gcl')
		self.__symlink('chromium-depot-tool', 'gclient')

setup(
	name="chromium-tools",
	version=get_version(),
	scripts=["chromium-depot-tool", "v8-create-tarball"],
	cmdclass={
		'sdist': my_sdist,
		'install_scripts': my_install_scripts,
	}
)
