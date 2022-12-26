from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent


def test_pe_versioninfo():
    pe_path = cur_dir_path / "test_data" / "HelloCSharp.exe_"
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    versioninfo = pe_analyzer.get_versioninfo()
    assert (
        versioninfo[3].get("name", "") == "FileDescription"
        and versioninfo[3].get("value", "") == "HelloCSharp"
    )
    assert (
        versioninfo[8].get("name", "") == "OriginalFilename"
        and versioninfo[8].get("value", "") == "HelloCSharp.exe"
    )
