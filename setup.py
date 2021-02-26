#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='avclass',
    version='1.0',
    packages=find_packages(include=[
        'avclass', 'avclass.*', 
        'avclass2', 'avclass2.*',
        'shared', 'shared.*',
    ]),
    entry_points={
        'console_scripts': [
            'avclass_labeler=avclass.avclass_labeler:real_main',
            'avclass2_labeler=avclass2.avclass2_labeler:real_main',
        ],
    },
    package_data = {
        'avclass' : ['data/*'],
        'avclass2' : ['data/*']
    },
)