# xanalyzer

静态分析文件和url，python3下运行。  

1. 文件
    输出文件类型  
    * PE文件
        * 编译时间
        * pdb路径
        * 签名验证
        * 查壳
2. url(website)
    TODO 做一些简单的爬取工作，手动分析会做的事情  

## 安装
使用pip安装：  
```r
pip install xanalyzer
```

从源码安装：  
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
python setup.py install
```

## 使用示例
```r
xanalyzer -f hello.exe
```
    
# 开发
```r
git clone https://github.com/qux-bbb/xanalyzer
cd xanalyzer
virtualenv venv
pip install -r requirements.txt
python setup.py develop
```
这样之后就可以开发调试了  

# 其它
TODO 创建一个data文件夹(命名带时间戳, 避免重复覆盖)，用于保存比较大的不适合输出的数据

这个项目的有些功能可能会用到:  
https://github.com/mitre/multiscanner  

参考链接:  
* python打包: https://www.jianshu.com/p/692bab7f8e07
* setuptools官方文档:  https://setuptools.readthedocs.io/en/latest/index.html
* PEiD查壳: https://github.com/erocarrera/pefile/blob/wiki/PEiDSignatures.md
