# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent

def test_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'Hello_upx.exe_'
    file_analyzer = FileAnalyzer(upxed_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    matches = pe_analyzer.get_packer_result()
    assert matches == ['UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser']


def test_pyinstaller_packer():
    pe_path = cur_dir_path / 'test_data' / 'pyinstaller_pack.exe_'
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    matches = pe_analyzer.get_packer_result()
    assert matches == ['PyInstaller, python37']
