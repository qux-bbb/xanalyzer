# xanalyzer

[简体中文](README.md)  

Simply analyze file and url, python3 is required.  

1. file
    - md5/sha256
    - file type
    - file size
    - string scan
    - PE file
        - PE size
        - compile time
        - pdb path
        - version info
        - certificate verify
        - section name
        - packer scan
        - resource section scan
    - ELF file
        - ELF size
        - packer scan
    - recommended tool
2. url(website)
    - domain to ip
    - robots.txt scan
    - site link scan(--deep)
    - site subdomain scan(--deep)

## Install
Method1 - install by pipx：  
```r
pipx install xanalyzer
# Upgrade by pipx, but can not check new version
pipx upgrade xanalyzer
```
pipx: https://pypa.github.io/pipx/  

Method2 - install from source：  
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python setup.py install
```

If your OS is Debian/Ubuntu, you need to install dependency：  
```r
sudo apt-get install libmagic1
```

## Usage help
```r
usage: xanalyzer [-h] (-f FILE [FILE ...] | -u URL | --version) [-s] [--deep]

Process some files and urls.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE [FILE ...], --file FILE [FILE ...]
                        analyze one or more files, can be a folder path
  -u URL, --url URL     analyze the url
  --version             print version info
  -s, --save            save log and data
  --deep                analyze deeply
```

## Usage example
```r
xanalyzer -f hello.exe
xanalyzer -u "https://www.baidu.com/s?wd=hello"
```

## Develop
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
virtualenv venv
pip install -r requirements.txt
python setup.py develop
```
Then you can develop and debug with pycharm or vscode  


## Other
Some functions of this project may be used:  
https://github.com/mitre/multiscanner  
