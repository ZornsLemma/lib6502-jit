#!/usr/bin/python

from __future__ import print_function
import subprocess

tests = [
    'basic-callback',
    'call-illegal-callback-modify-code',
    'irq-nmi',
    'setjmp-trick',
    'stack-code-brk',
    'stack-code-jsr',
    'write-callback-modify-code'
]

test_args = [
    '-mi',
    '-mh',
    '-mc -mx 1',
    '-mc'
]
        
print('1..', len(tests) * len(test_args), sep='')
i = 1
for test_arg in test_args:
    for test in tests:
        result = subprocess.check_output(['test/' + test] + test_arg.split())
        expected_result = open('test/' + test + '.mst', 'rb').read()
        if result == expected_result:
            print('ok', i, test, test_arg)
        else:
            print('not ok', i, test, test_arg)
        i += 1
