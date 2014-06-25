#!/usr/bin/python

from __future__ import print_function
import glob
import os
import subprocess

os.chdir('test')

# It's quite likely the "xa" assembler is not installed; don't generate
# scary test failures if that's the case.
xa_installed = True
try:
    result = subprocess.check_output(['xa', '--version'])
    if result.find(b'xa65') == -1:
        xa_installed = False
except:
    xa_installed = False

# By default we skip slow tests (those with names starting z-) in '-mc'
# modes.
skip_slow_mc = (os.getenv('RUN_SLOW_TESTS', '0') == '0')

# Since we didn't have to hard-code the test names in the Makefile.am, we
# use wildcards here.
tests = sorted([t for t in glob.glob('*.xa') if t != 'config.xa'])

test_args = [
    '-mi',
    '-mh',
    '-mc -mx 1',
    '-mc'
]
        
print('1..', len(tests) * len(test_args), sep='')
i = 0
for test_arg in test_args:
    for test in tests:
        i += 1
        basename = test[0:-3]

        if not xa_installed:
            print('ok', i, '# skipped (xa not installed):', test, test_arg)
            continue

        if skip_slow_mc and basename[0:2] == 'z-' and test_arg[0:3] == '-mc':
            print('ok', i, '# skipped (slow -mc):', test, test_arg)
            continue

        xa_out = basename + '.mc'
        subprocess.check_call(['xa', '-o', xa_out, test])
        result = subprocess.check_output(
            ['../run6502', '-l', '1e00', xa_out, '-R', '1e00', '-G', 'ffe0', 
             '-P', 'ffee', '-X', 'f000'] + test_arg.split())
        expected_result = open(basename + '.mst', 'rb').read()
        if result == expected_result:
            print('ok', i, test, test_arg)
        else:
            print('not ok', i, test, test_arg)
