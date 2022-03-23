# coding:utf8

import os
import re
import json
import magic
from pathlib import Path
from hashlib import md5
from zipfile import ZipFile

from xanalyzer.utils import log
from xanalyzer.file_process.pe import PeAnalyzer
from xanalyzer.config import Config


class FileAnalyzer():
    file_path = None
    file_size = None
    file_type = None

    def __init__(self, file_path):
        self.file_path = file_path
        self.file_size = os.path.getsize(self.file_path)
        self.file_type = self.guess_type()

    def guess_type(self):
        # return magic.from_file(self.file_path)
        # magic.from_file不能通过中文路径读取文件，暂时使用magic.from_buffer
        the_file = open(self.file_path, 'rb')
        the_content = the_file.read()
        the_file.close()
        the_file_type = magic.from_buffer(the_content)
        if the_file_type.startswith('Zip archive data'):
            the_zip = ZipFile(self.file_path)
            zip_namelist = the_zip.namelist()
            the_zip.close()
            if 'AndroidManifest.xml' in zip_namelist:
                the_file_type = f'{the_file_type}, APK(Android application package)'
            elif '[Content_Types].xml' in zip_namelist:
                if 'word/document.xml' in zip_namelist:
                    the_file_type = 'Microsoft Word 2007+'
                elif 'xl/workbook.xml' in zip_namelist:
                    the_file_type = 'Microsoft Excel 2007+'
                elif 'ppt/presentation.xml' in zip_namelist:
                    the_file_type = 'Microsoft PowerPoint 2007+'
        return the_file_type

    @staticmethod
    def get_windows_style_file_size(tmp_size):
        """
        得到windows风格的文件大小展示
        参考: https://stackoverflow.com/a/1094933/7164926
        [0, 1024字节): 直接展示size
        [1024字节, 1000YB):
            如果整数位数大于3，则以下一单位计数；
            如果整数位数为3，保留整数位置，有小数则略去；
            如果整数位数小于3，以小数展示
                小数展示规则：整数位数和小数位数加起来共3位显示(不包括小数点)，后面数字略去
        [1000YB, +): 直接展示size
        """
        if tmp_size == 0:
            return '0 字节'

        bytes_size = ' ({} 字节)'.format(format(tmp_size, ','))
        if tmp_size < 1024:
            return f'{tmp_size} 字节{bytes_size}'
        tmp_formatted_size = 0
        tmp_unit = ''
        for unit in ['字节', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']:
            if abs(tmp_size) < 1000.0:
                tmp_formatted_size = tmp_size
                tmp_unit = unit
                break
            tmp_size /= 1024.0
        else:
            tmp_formatted_size = tmp_size
            tmp_unit = 'YB'

        if tmp_unit == 'YB' and tmp_formatted_size >= 1000:
            return f'{tmp_formatted_size} YB{bytes_size}'

        tmp_formatted_size = str(tmp_formatted_size)
        if '.' in tmp_formatted_size[:3]:
            formatted_size = '{:0<4}'.format(tmp_formatted_size[:4])
        else:
            formatted_size = tmp_formatted_size[:3]

        return f'{formatted_size} {tmp_unit}{bytes_size}'

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

    def get_tool_recommendations(self):
        with open(Config.tools_info_path, 'r') as f:
            tools_info = json.load(f)
        recommended_tool_info_list = []
        if 'UPX compressed' in self.file_type:
            recommended_tool_info_list.append(
                ['UPX', tools_info.get('UPX')]
            )
        if 'Mono/.Net assembly' in self.file_type:
            recommended_tool_info_list.append(
                ['dnSpy', tools_info.get('dnSpy')]
            )
        if 'APK(Android application package)' in self.file_type:
            recommended_tool_info_list.append(
                ['JADX', tools_info.get('JADX')]
            )
        return recommended_tool_info_list

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

    def tool_recommendations_scan(self):
        recommended_tool_info_list = self.get_tool_recommendations()
        if recommended_tool_info_list:
            log.info('recommended tool info:')
            for recommended_tool_info in recommended_tool_info_list:
                log.info(f'    {recommended_tool_info[0]}: {recommended_tool_info[1]}')

    def search_str(self, want='ctf'):
        # TODO 查找敏感字符串
        pass

    def run(self):
        log.info('md5: {}'.format(self.get_md5()))
        log.info('file type: {}'.format(self.file_type))
        log.info('file size: {}'.format(self.file_size))
        log.info('windows style file type: {}'.format(self.get_windows_style_file_size(self.file_size)))

        self.str_scan()
        if self.file_type.startswith('PE'):
            pe_analyzer = PeAnalyzer(self.file_path)
            pe_analyzer.run()
        self.tool_recommendations_scan()
