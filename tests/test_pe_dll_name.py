from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent


def test_pe_pdb():
    pe_path = cur_dir_path / "test_data" / "Hello64.dll_"
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    dll_name = pe_analyzer.get_dll_name()
    assert dll_name == b"SampleDll.dll"
