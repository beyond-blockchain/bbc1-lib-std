# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""
This is a developers tool used for developing libraries and subsystems for
BBc-1 (Beyond Blockchain One), before making these pip-installable.
This tool copies source files being developed onto the core source code tree.
"""
import argparse
import os
import subprocess

DIRS = ['bbc1', 'examples', 'lib', 'tests', 'utils']
EXTS = ['py', 'sol']


def copy_dir(coredir, dir, verbose=False, test=False, remove=False):

    files = os.listdir(dir)
    for filename in files:
        if filename[:1] != '_':
            s = filename.split('.')
            if s[len(s) - 1] in EXTS:
                if remove:
                    remove_file(coredir, dir, filename, verbose=verbose,
                            test=test)
                else:
                    copy_file(coredir, dir, filename, verbose=verbose,
                            test=test)
            else:
                path = os.path.join(dir, filename)
                if os.path.isdir(path):
                    copy_dir(coredir, path, verbose=verbose, test=test,
                            remove=remove)


def copy_file(coredir, dir, filename, verbose=False, test=False):

    source = os.path.join(dir, filename)
    dest = os.path.join(coredir, dir)
    if not os.path.exists(dest) and not test:
        os.mkdir(dest)
    if verbose:
        print('cp', source, os.path.join(dest, '.'))
    if not test:
        subprocess.call(['cp', source, os.path.join(dest, '.')])


def parse_arguments():

    argparser = argparse.ArgumentParser(
        description='Copy files being developed onto core source code tree'
                ' or remove them.'
    )

    argparser.add_argument('-d', '--coredir', type=str, action='store',
            help='directory of BBc-1 core', default='bbc1')
    argparser.add_argument('-rm', '--remove', action='store_true',
            help='remove copied files (leave directories)')
    argparser.add_argument('-t', '--test', action='store_true',
            help='does not make copies or directories')
    argparser.add_argument('-v', '--verbose', action='store_true',
            help='verbose output')

    return argparser.parse_args()


def remove_file(coredir, dir, filename, verbose=False, test=False):

    dest = os.path.join(coredir, dir)
    if verbose:
        print('rm', os.path.join(dest, filename))
    if not test:
        subprocess.call(['rm', os.path.join(dest, filename)])


if __name__ == '__main__':

    args = parse_arguments()
    dest = os.path.join('..', args.coredir)

    for dir in DIRS:
        if os.path.exists(dir):
            copy_dir(dest, dir, verbose=args.verbose, test=args.test,
                    remove=args.remove)


# end of devmerge.py
