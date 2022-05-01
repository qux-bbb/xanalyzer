# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer


cur_dir_path = Path(__file__).parent


def test_pe_size():
    pe_path = cur_dir_path / 'test_data' / 'HelloCSharp.exe_append_data_'

    pe_analyzer = PeAnalyzer(pe_path)
    pe_size = pe_analyzer.get_pe_size()
    assert pe_size == 0x1200

    file_analyzer = FileAnalyzer(pe_path)
    assert file_analyzer.file_size == 0x1205
