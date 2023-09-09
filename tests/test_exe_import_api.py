from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent


def test_exe_import_api():
    pe_path = cur_dir_path / "test_data" / "Hello_upx.exe_"
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    exe_import_api_list = pe_analyzer.get_exe_import_api_list()
    assert exe_import_api_list == [
        "KERNEL32.LoadLibraryA",
        "KERNEL32.ExitProcess",
        "KERNEL32.GetProcAddress",
        "KERNEL32.VirtualProtect",
    ]
