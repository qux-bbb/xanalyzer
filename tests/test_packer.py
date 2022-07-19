# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer
from xanalyzer.file_process.elf import ElfAnalyzer

cur_dir_path = Path(__file__).parent


def test_exe_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'Hello_upx.exe_'
    file_analyzer = FileAnalyzer(upxed_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    matches = pe_analyzer.get_packer_result()
    assert matches == ['UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser']


def test_elf_upx_packer():
    upxed_path = cur_dir_path / 'test_data' / 'Hello64_elf_static_upx_'
    file_analyzer = FileAnalyzer(upxed_path)
    elf_analyzer = ElfAnalyzer(file_analyzer)
    matches = elf_analyzer.get_packer_result()
    assert matches == ['UPX 3.96']


def test_pyinstaller_packer():
    pe_path = cur_dir_path / 'test_data' / 'pyinstaller_pack.exe_'
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    matches = pe_analyzer.get_packer_result()
    assert matches == ['PyInstaller, python37']


def test_shc_packer():
    elf_path = cur_dir_path / 'test_data' / 'hello64_elf_shc_'
    file_analyzer = FileAnalyzer(elf_path)
    elf_analyzer = ElfAnalyzer(file_analyzer)
    matches = elf_analyzer.get_packer_result()
    assert matches == ['Shc, Shell script compiler, https://github.com/neurobin/shc']
