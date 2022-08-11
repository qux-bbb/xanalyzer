# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer


cur_dir_path = Path(__file__).parent


def test_pe_resource_picture():
    pe_path = cur_dir_path / 'test_data' / 'pyinstaller_pack.exe_'

    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    resource_type_dict = pe_analyzer.get_resource_type_dict()
    assert resource_type_dict['3_1_0'][1] == ['.ico']


def test_pe_resource_pe():
    pe_path = cur_dir_path / 'test_data' / 'HelloB_resource_pe.exe_'

    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    resource_type_dict = pe_analyzer.get_resource_type_dict()
    assert resource_type_dict['None:HELLOA_102_2052'][1] == ['.exe']
