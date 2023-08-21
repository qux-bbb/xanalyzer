from pathlib import Path

from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_str():
    pe_path = cur_dir_path / "test_data" / "str.txt"

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=3)
    assert file_analyzer.get_strs() == [b"333", b"4444", b"55555"]

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=4)
    assert file_analyzer.get_strs() == [b"4444", b"55555"]

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=5)
    assert file_analyzer.get_strs() == [b"55555"]


def test_wide_str():
    pe_path = cur_dir_path / "test_data" / "wide_str.txt"

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=3)
    assert file_analyzer.get_wide_strs() == [
        b"3\x003\x003\x00",
        b"4\x004\x004\x004\x00",
        b"5\x005\x005\x005\x005\x00",
    ]

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=4)
    assert file_analyzer.get_wide_strs() == [
        b"4\x004\x004\x004\x00",
        b"5\x005\x005\x005\x005\x00",
    ]

    file_analyzer = FileAnalyzer(file_path=pe_path, minstrlen=5)
    assert file_analyzer.get_wide_strs() == [b"5\x005\x005\x005\x005\x00"]
