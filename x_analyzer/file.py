# coding:utf8

import magic

from x_analyzer.utils import log, log_red
from x_analyzer.file_process.pe import PeAnalyzer


class FileAnalyzer():
    file_type = None
    file_path = None

    def __init__(self, file_path):
        self.file_path = file_path
        self.file_type = self.get_type()
    
    def get_type(self):
        return magic.from_file(self.file_path)
    
    def search_str(self, want='ctf'):
        # TODO 查找敏感字符串
        pass

    def run(self):
        log('file type: {}'.format(self.file_type))
        if self.file_type.startswith('PE'):
            pe_analyzer = PeAnalyzer(self.file_path)
            pe_analyzer.run()