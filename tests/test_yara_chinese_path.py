from pathlib import Path
from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_yara_chinese_path():
    upxed_path = cur_dir_path / "test_data" / "中文名测试.txt"
    file_analyzer = FileAnalyzer(upxed_path)
    result = file_analyzer.packer_yara_match()
    assert result == []
