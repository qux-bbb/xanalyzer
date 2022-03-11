# coding:utf8

from pathlib import Path
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent

def test_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'HelloCSharp.exe_'
    pe_analyzer = PeAnalyzer(upxed_path)
    versioninfo = pe_analyzer.get_versioninfo()
    assert versioninfo[3].get('name', '') == 'FileDescription' and versioninfo[3].get('value', '') == 'HelloCSharp'
    assert versioninfo[8].get('name', '') == 'OriginalFilename' and versioninfo[8].get('value', '') == 'HelloCSharp.exe'
