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
        - DLL name
        - EXE import table check
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
Install by pipx：  
```r
# pipx: https://pypa.github.io/pipx/  
pip install pipx
pipx ensurepath
pipx install xanalyzer
# Upgrade by pipx, but can not check new version
pipx upgrade xanalyzer
```

If your OS is Debian/Ubuntu, you need to install dependency：  
```r
sudo apt-get install libmagic1
```

## Usage help
```r
usage: xanalyzer [-h] (-f FILE [FILE ...] | -u URL | --version) [-s] [--deep]
                 [--minstrlen MINSTRLEN]

Process some files and urls. 'xa' can be used instead of 'xanalyzer'

optional arguments:
  -h, --help            show this help message and exit
  -f FILE [FILE ...], --file FILE [FILE ...]
                        analyze one or more files, can be a folder path
  -u URL, --url URL     analyze the url
  --version             print version info
  -s, --save            save log and data
  --deep                analyze deeply
  --minstrlen MINSTRLEN
                        minimum length of the string to be extracted, default
                        4, not less than 2
```

## Usage example
```r
xanalyzer -f hello.exe
xanalyzer -u "https://www.baidu.com/s?wd=hello"
xa -f hello.exe
```

## Develop
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python -m venv venv
# use venv in windws: .\venv\Scripts\activate
# use venv in linux: source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements.my.txt
python setup.py develop
# exit venv: deactivate
```
Then you can develop and debug with pycharm or vscode  


## Other
Some functions of this project may be used:  
https://github.com/mitre/multiscanner  
