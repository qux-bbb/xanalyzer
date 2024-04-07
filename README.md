# xanalyzer

[English](README-en.md)  

简单分析文件和url，python3下运行。  

1. 文件
    - md5/sha256
    - 文件类型
    - 文件大小
    - 字符串扫描
    - PE文件
        - PE大小
        - 编译时间
        - pdb路径
        - 版本信息
        - 证书验证
        - 节区名称
        - DLL名称
        - EXE导入表检查
        - 查壳
        - 资源段扫描
    - ELF文件
        - ELF大小
        - 查壳
    - 建议使用的工具
2. url(website)
    - 域名解析ip
    - 获取robots.txt文件
    - 站内链接扫描(--deep)
    - 站内子域名扫描(--deep)

## 安装
使用pipx安装：  
```r
# pipx: https://pypa.github.io/pipx/  
pip install pipx
pipx ensurepath
pipx install xanalyzer
# 还可以用来升级，但是不能检查新版本
pipx upgrade xanalyzer
```

如果系统是 Debian/Ubuntu，需要安装依赖：  
```r
sudo apt-get install libmagic1
```

## 使用帮助
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

## 使用示例
```r
xanalyzer -f hello.exe
xanalyzer -u "https://www.baidu.com/s?wd=hello"
xa -f hello.exe
```

## 开发
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python -m venv venv
# windws使用虚拟环境: .\venv\Scripts\activate
# linux使用虚拟环境: source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements.my.txt
python setup.py develop
# 退出虚拟环境: deactivate
```
这样之后就可以用pycharm或vscode开发调试了  

## 打包发布
该步骤仅本人使用  

打包前确保版本号和CHANGELOG.md已更新，清空dist文件夹  

安装依赖、通过测试项、打包：  
```r
# windws使用虚拟环境: .\venv\Scripts\activate
# linux使用虚拟环境: source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements.my.txt
pytest
python -m build
# 退出虚拟环境: deactivate
```

重新打开一个命令行，转到dist文件夹下本地安装，检查基本功能，举例：  
```r
pipx uninstall xanalyzer
pipx install ./xanalyzer-0.2.3.tar.gz
xanalyzer --version
xanalyzer -f ./xanalyzer-0.2.3.tar.gz
```

在github创建Release  
1. 标题为`xanalyzer <version>`，如: `xanalyzer v0.2.0`  
2. 内容基于CHANGELOG.md做一些修改
3. 将dist文件夹下所有文件传到Release页面  
然后发布即可  

将文件传到pypi(需要账号密码)  
```r
python -m twine upload --repository pypi dist/*
```

## 其它
这个项目的有些功能可能会用到:  
https://github.com/mitre/multiscanner  

参考链接:  
- python打包: https://www.jianshu.com/p/692bab7f8e07
- setuptools官方文档:  https://setuptools.readthedocs.io/en/latest/index.html
- PEiD查壳: https://github.com/erocarrera/pefile/blob/wiki/PEiDSignatures.md
