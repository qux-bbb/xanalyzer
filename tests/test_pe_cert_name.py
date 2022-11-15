from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent


def test_pe_pdb():
    pe_path = cur_dir_path / "test_data" / "java.exe_"
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    cert_info_list = pe_analyzer.verify_cert()
    assert (
        cert_info_list[0].get("subject", "")
        == "EMAIL=pkiadm_us@oracle.com, CN=Oracle America\, Inc., OU=Software Engineering, O=Oracle America\, Inc., L=Redwood City, ST=California, C=US"
    )
