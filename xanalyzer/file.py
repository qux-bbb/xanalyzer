# coding:utf8

import os
import re
import magic
from pathlib import Path
from hashlib import md5

from xanalyzer.utils import log
from xanalyzer.file_process.pe import PeAnalyzer
from xanalyzer.config import Config


class FileAnalyzer():
    file_type = None
    file_path = None

    def __init__(self, file_path):
        self.file_path = file_path
        self.file_type = self.get_type()
    
    def get_type(self):
        return magic.from_file(self.file_path)

    def get_md5(self):
        the_file = open(self.file_path, 'rb')
        file_content = the_file.read()
        the_file.close()
        md5_value = md5(file_content).hexdigest()
        return md5_value

    def get_strs(self):
        the_file = open(self.file_path, 'rb')
        file_content = the_file.read()
        the_file.close()
        all_strs = re.findall(rb'[\x21-\x7e]{4,}', file_content)
        return all_strs

    def str_scan(self):
        all_strs = self.get_strs()
        if all_strs:
            log.info(f'str num: {len(all_strs)}')
            if Config.conf['save_flag']:
                str_file_name = Path(self.file_path).name+'_strings.txt'
                str_data_path = os.path.join(Config.conf['analyze_data_path'], str_file_name)
                with open(str_data_path, 'wb') as f:
                    for a_str in all_strs:
                        f.write(a_str+b'\n')
                log.info(f'{str_file_name} saved')

    def search_str(self, want='ctf'):
        # TODO 查找敏感字符串
        pass

    def run(self):
        log.info('md5: {}'.format(self.get_md5()))
        log.info('file type: {}'.format(self.file_type))
        self.str_scan()
        if self.file_type.startswith('PE'):
            pe_analyzer = PeAnalyzer(self.file_path)
            pe_analyzer.run()
