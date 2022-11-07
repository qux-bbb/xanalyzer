from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent

def test_pe_pdb():
    pe_path = cur_dir_path / 'test_data' / 'HelloCSharp.exe_'
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    pdb_path = pe_analyzer.get_pdb_path()
    assert pdb_path == r'D:\files\vs2019\sources\HelloCSharp\HelloCSharp\obj\Release\HelloCSharp.pdb'
