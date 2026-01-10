import time
from pathlib import Path

from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_get_special_str_speed():
    pe_path = cur_dir_path / "test_data" / "47502fe8e2f99eeff7a4939eab9858ebc3e4ab7bde8e615cfc4066d13cd860be_test_get_special_str_speed"

    file_analyzer = FileAnalyzer(file_path=pe_path)

    start_time = time.time()
    file_analyzer.get_special_strs()
    end_time = time.time()
    assert end_time - start_time < 60
