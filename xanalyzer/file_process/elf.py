# coding:utf8

import re
from xanalyzer.utils import log


class ElfAnalyzer:
    file_analyzer = None

    def __init__(self, file_analyzer):
        self.file_analyzer = file_analyzer

    def get_packer_result(self):
        the_file = open(self.file_analyzer.file_path, 'rb')
        file_content = the_file.read()
        the_file.close()
    
        # Check Shc
        if b'E: neither argv[0] nor $_ works.' in file_content:
            matches = ['Shc, Shell script compiler, https://github.com/neurobin/shc']
            return matches
        
        # Check UPX
        if b'$Info: This file is packed with the UPX executable packer' in file_content:
            upx_ver_s = re.search(rb'\$Id: (UPX .+?) Copyright', file_content)
            if upx_ver_s:
                matches = [upx_ver_s.group(1).decode()]
            else:
                matches = ['UPX unknown version']
            return matches
            
        return None

    def packer_scan(self):
        """
        查壳
        """
        matches = self.get_packer_result()
        if matches:
            self.file_analyzer.packer_list.extend(matches)
            log.info('packer: {}'.format(matches))

    def run(self):
        self.packer_scan()
