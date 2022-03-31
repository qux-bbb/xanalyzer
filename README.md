# xanalyzer

静态分析文件和url，python3下运行。  

1. 文件
    - md5
    - 文件类型
    - 文件大小
    - 字符串扫描
    - PE文件
        - 编译时间
        - pdb路径
        - 证书验证
        - 查壳
    - 建议使用的工具
2. url(website)
    - 域名解析ip
    - 获取robots.txt文件
    - 站内链接扫描
    - 站内子域名扫描

## 安装
方法1 - 使用pip安装：  
```r
pip install xanalyzer
```

方法2 - 从源码安装：  
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python setup.py install
```

## 使用帮助
```r
usage: xanalyzer [-h] (-f FILE [FILE ...] | -u URL) [-s]

Process some files and urls.

optional arguments:
  -h, --help            show this help message and exit 
  -f FILE [FILE ...], --file FILE [FILE ...]
                        analyze one or more files, can be a folder path
  -u URL, --url URL     analyze the url
  -s, --save            save log and data
```

## 使用示例
```r
xanalyzer -f hello.exe
xanalyzer -u "https://www.baidu.com/s?wd=hello"
```
    
# 开发
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
virtualenv venv
pip install -r requirements.txt
python setup.py develop
```
这样之后就可以用pycharm或vscode开发调试了  

# 其它
这个项目的有些功能可能会用到:  
https://github.com/mitre/multiscanner  

参考链接:  
- python打包: https://www.jianshu.com/p/692bab7f8e07
- setuptools官方文档:  https://setuptools.readthedocs.io/en/latest/index.html
- PEiD查壳: https://github.com/erocarrera/pefile/blob/wiki/PEiDSignatures.md
