# coding:utf8

import magic

from xanalyzer.utils import log
from xanalyzer.file_process.pe import PeAnalyzer


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
        log.info('file type: {}'.format(self.file_type))
        if self.file_type.startswith('PE'):
            pe_analyzer = PeAnalyzer(self.file_path)
            pe_analyzer.run()