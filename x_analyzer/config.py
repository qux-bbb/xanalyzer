# coding:utf8

from pathlib import Path


class Config:
    home_dir = Path(__file__).parent
    # UserDB.TXT文件默认是GBK编码, 需要简单处理一下, 去掉乱码, 新的UserDB.TXT加了新的规则, peutils解析不了
    peid_signature_path = home_dir / 'data' / 'UserDB.TXT'
