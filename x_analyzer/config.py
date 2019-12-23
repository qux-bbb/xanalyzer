# coding:utf8

from pathlib import Path
import time


class Config:
    home_dir = Path(__file__).parent
    log_file_path = 'x_analyzer.log'
    # UserDB.TXT文件默认是GBK编码, 需要简单处理一下, 去掉乱码, 新的UserDB.TXT加了新的规则, peutils解析不了
    peid_signature_path = home_dir / 'data' / 'UserDB.TXT'

    @classmethod
    def set_log_file_path(cls):
        cur_time = time.strftime('%Y%m%d_%H%M%S')
        cls.log_file_path = 'x_analyzer_{}.log'.format(cur_time)