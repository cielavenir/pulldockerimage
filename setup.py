from setuptools import setup

import sys

setup(
    name='pulldockerimage',
    description='pull docker image and send to stdout',
    long_description=open("readme.md").read(),
    long_description_content_type='text/markdown',
    version='0.0.1.0',
    url='https://github.com/cielavenir/pulldockerimage',
    license='BSD-2-Clause',
    author='cielavenir',
    author_email='cielartisan@gmail.com',
    py_modules=['pulldockerimage'],
    zip_safe=False,
    # include_package_data=True,
    platforms='any',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: Public Domain',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Software Development :: Libraries',
        'Topic :: Utilities',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
    ]
)
