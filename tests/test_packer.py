# coding:utf8

from pathlib import Path
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent

def test_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'Hello_upx.exe_'
    pe_analyzer = PeAnalyzer(upxed_path)
    matches = pe_analyzer.get_peid_result()
    assert matches == ['UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser']
