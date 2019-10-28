import subprocess
from os import path
from setuptools import setup
from setuptools.command.install import install


here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            pass
        except Exception as e:
            print(e)
            print("-- Error message--")
            exit(1)
        else:
            install.run(self)


bbc1_requires = []

bbc1_packages = [
                 'bbc1',
                 'bbc1.lib'
                 ]

bbc1_commands = []

bbc1_classifiers = [
                    'Development Status :: 4 - Beta',
                    'Programming Language :: Python :: 3.5',
                    'Programming Language :: Python :: 3.6',
                    'Topic :: Software Development']

setup(
    name='bbc1-lib-std',
    version='0.16',
    description='Standard library of Beyond Blockchain One',
    long_description=readme,
    url='https://github.com/beyond-blockchain/bbc1-lib-std',
    author='beyond-blockchain.org',
    author_email='bbc1-dev@beyond-blockchain.org',
    license='Apache License 2.0',
    classifiers=bbc1_classifiers,
    cmdclass={'install': MyInstall},
    packages=bbc1_packages,
    scripts=bbc1_commands,
    install_requires=bbc1_requires,
    zip_safe=False)

