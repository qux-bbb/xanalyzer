from setuptools import setup, find_packages


setup(
    name="xanalyzer",
    version=open("xanalyzer/VERSION", "r").read(),
    packages=find_packages(),
    package_data={
        "xanalyzer": [
            "data/UserDB.TXT",
            "data/yara_rules/packers/*",
            "data/tools_info.json",
            "VERSION",
        ],
    },
    author="qux-bbb",
    description="Analyzer for files and urls",
    long_description=open("README.md", "r", encoding="utf8").read(),
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "xanalyzer = xanalyzer.main:main",
            "xa = xanalyzer.main:main",
        ],
    },
    install_requires=open("requirements.txt", "r").read().split("\n"),
)
