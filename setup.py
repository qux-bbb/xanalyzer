from setuptools import setup, find_packages


setup(
    name='x_analyzer',
    version='0.1',
    packages=find_packages(),
    package_data={
        'x_analyzer': ['data/UserDB.TXT'],
    },
    author='qux-bbb',
    description='Analyzer for files and urls',
    long_description=open('README.md', 'r', encoding='utf8').read(),
    entry_points={
        'console_scripts': [
            'x_analyzer = x_analyzer.main:main',
        ],
    },
    install_requires=open('requirements.txt', 'r').read().split('\n'),
)