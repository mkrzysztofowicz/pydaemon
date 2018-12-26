from setuptools import setup

version = {}
with open('pydaemon/version.py') as fp:
    exec(fp.read(), version)

setup(
    name='pydaemon',
    packages=['pydaemon'],
    version=version['pydaemon_version'],
    author='Michal Krzysztofowicz',
    author_email='mike@frozen-geek.net',
    url='https://frozen-geek.net/'
)
