from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.elf import ElfAnalyzer


cur_dir_path = Path(__file__).parent


def test_elf_size():
    pe_path = cur_dir_path / "test_data" / "hello32_elf_append_data_"

    file_analyzer = FileAnalyzer(pe_path)
    assert file_analyzer.file_size == 0x3ce5

    elf_analyzer = ElfAnalyzer(file_analyzer)
    elf_size = elf_analyzer.get_elf_size()
    assert elf_size == 0x3ce0
