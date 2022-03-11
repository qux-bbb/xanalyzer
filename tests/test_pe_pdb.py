# coding:utf8

from pathlib import Path
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent

def test_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'HelloCSharp.exe_'
    pe_analyzer = PeAnalyzer(upxed_path)
    pdb_path = pe_analyzer.get_pdb_path()
    assert pdb_path == r'D:\files\vs2019\sources\HelloCSharp\HelloCSharp\obj\Release\HelloCSharp.pdb'
