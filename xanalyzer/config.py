# coding:utf8

import os
import time
from pathlib import Path


class Config:
    home_dir = Path(__file__).parent
    # UserDB.TXT文件默认是GBK编码, 需要简单处理一下, 去掉乱码, 新的UserDB.TXT加了新的规则, peutils解析不了
    peid_signature_path = home_dir / 'data' / 'UserDB.TXT'
    tools_info_path = home_dir / 'data' / 'tools_info.json'
    VERSION = open(home_dir / 'VERSION', 'r').read().strip()

    conf = {}

    @classmethod
    def init(cls, save_flag):
        cls.conf['save_flag'] = save_flag
        if save_flag:
            cur_time = time.strftime('%Y%m%d_%H%M%S')
            analyze_path = f'xanalyzer_{cur_time}'
            analyze_data_path = os.path.join(analyze_path, 'data')
            cls.conf['analyze_path'] = analyze_path
            cls.conf['analyze_data_path'] = analyze_data_path
            os.makedirs(analyze_path, exist_ok=True)
            os.makedirs(analyze_data_path, exist_ok=True)
