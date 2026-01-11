from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.jpg import JpgAnalyzer


cur_dir_path = Path(__file__).parent


def test_jpg_tail():
    jpg_path = cur_dir_path / "test_data" / "hello.jpg_append_data_"

    file_analyzer = FileAnalyzer(jpg_path)
    assert file_analyzer.file_size == 1860

    jpg_analyzer = JpgAnalyzer(file_analyzer)
    weird_jpg_info = jpg_analyzer.get_weird_jpg_info()
    assert weird_jpg_info["is_weird"] == True
    assert weird_jpg_info["has_ffd9"] == True
    assert weird_jpg_info["possible_jpg_size"] == 1855
    assert weird_jpg_info["possible_extra_size"] == 5
    assert weird_jpg_info["extra"] == b"hello"
