# xanalyzer

静态分析文件和url，python3下运行。  

1. 文件
    - md5
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
        - 查壳
        - 资源段扫描
    - ELF文件
        - 查壳
    - 建议使用的工具
2. url(website)
    - 域名解析ip
    - 获取robots.txt文件
    - 站内链接扫描
    - 站内子域名扫描

## 安装
方法1 - 使用pipx安装：  
```r
pipx install xanalyzer
```
pipx: https://pypa.github.io/pipx/  

方法2 - 从源码安装：  
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python setup.py install
```

如果系统是 Debian/Ubuntu，需要安装依赖：  
```r
sudo apt-get install libmagic1
```

## 使用帮助
```r
usage: xanalyzer [-h] (-f FILE [FILE ...] | -u URL | --version) [-s]

Process some files and urls.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE [FILE ...], --file FILE [FILE ...]
                        analyze one or more files, can be a folder path
  -u URL, --url URL     analyze the url
  --version             print version info
  -s, --save            save log and data
```

## 使用示例
```r
xanalyzer -f hello.exe
xanalyzer -u "https://www.baidu.com/s?wd=hello"
```
    
## 开发
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
virtualenv venv
pip install -r requirements.txt
python setup.py develop
```
这样之后就可以用pycharm或vscode开发调试了  

## 打包发布
该步骤仅本人使用  
```r
pip install -r requirements.my.txt
python setup.py sdist bdist_wheel
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
