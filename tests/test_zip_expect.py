from pathlib import Path
from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_zip_expect():
    broken_zip_path = cur_dir_path / "test_data" / "3ba5350ecef80a058f5e72ee2ee80c69d7718b9d344ff4a661e1ccfbb1d119f9_broken_zip"
    file_analyzer = FileAnalyzer(broken_zip_path)
    assert file_analyzer.file_type.startswith("Zip archive data")
    assert file_analyzer.possible_extension_names == [".zip"]
