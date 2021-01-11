from setuptools import find_packages, setup


setup(
    name='AVClass',
    version='2.0.0',
    description='Tag and label malware samples',
    license='LICENSE',
    packages=find_packages(),
    install_requires=[],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
    entry_points={
        'console_scripts': [
            'avclass = avclass.labeler:main',
            'avclass-validate = avclass.input_checker:main',
        ],
    })
