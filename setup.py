# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='foundation_security_advisories',
    version='1.0.0',
    description='Tools supporting the Mozilla Foundation Security Advisories',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/mozilla/foundation-security-advisories',
    author='Tom Ritter',
    license='MPL-2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python :: 3'
    ],
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[
        'PyYAML==5.4',
        'Markdown',
        'python-dateutil==2.4.2',
        'schema==0.7.2',
        'requests'],
    entry_points={
        "console_scripts": [
            "update_hof = foundation_security_advisories.update_hof:main",
            "check_advisories = foundation_security_advisories.check_advisories:main"
        ]
    }
)
