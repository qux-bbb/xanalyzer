# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer


cur_dir_path = Path(__file__).parent


def test_normal_pe_compile_time():
    weird_pe_path = cur_dir_path / 'test_data' / 'Hello32.exe_'

    file_analyzer = FileAnalyzer(weird_pe_path)
    assert file_analyzer.file_type == 'PE32 executable (console) Intel 80386, for MS Windows'

    pe_analyzer = PeAnalyzer(weird_pe_path)
    compile_time = pe_analyzer.get_compile_time()
    assert compile_time == '2022-03-27 14:38:47'


def test_weird_pe_compile_time():
    """
    "PE"的位置很奇怪
    """
    weird_pe_path = cur_dir_path / 'test_data' / 'a3398f91815a1a025fd19ce86b9fb88160047b5d78973b352d266ef1bd971e6d_zeus_prg_40'

    file_analyzer = FileAnalyzer(weird_pe_path)
    assert file_analyzer.file_type == 'MS-DOS executable'

    pe_analyzer = PeAnalyzer(weird_pe_path)
    compile_time = pe_analyzer.get_compile_time()
    assert compile_time == '2006-11-06 11:44:05'
