import re
from elftools.elf.elffile import ELFFile
from xanalyzer.utils import log


class ElfAnalyzer:
    file_analyzer = None

    def __init__(self, file_analyzer):
        self.file_analyzer = file_analyzer

    def get_elf_size(self):
        """
        计算真实ELF大小
        """

        the_file = open(self.file_analyzer.file_path, "rb")
        elf_file = ELFFile(the_file)
        elf_size = (
            elf_file.header.e_shoff
            + elf_file.header.e_shentsize * elf_file.header.e_shnum
        )
        the_file.close()

        return elf_size

    def get_packer_result(self):
        the_file = open(self.file_analyzer.file_path, "rb")
        file_content = the_file.read()
        the_file.close()

        # Check Shc
        if b"E: neither argv[0] nor $_ works." in file_content:
            matches = ["Shc, Shell script compiler, https://github.com/neurobin/shc"]
            return matches

        # Check UPX
        if b"$Info: This file is packed with the UPX executable packer" in file_content:
            upx_ver_s = re.search(rb"\$Id: (UPX .+?) Copyright", file_content)
            if upx_ver_s:
                matches = [upx_ver_s.group(1).decode()]
            else:
                matches = ["UPX unknown version"]
            return matches

        return None

    def elf_size_scan(self):
        """
        判断文件大小是否和纯ELF匹配，是否有多余数据
        因为是ELF的特殊情况，不考虑和文件大小放在一起
        """
        elf_size = self.get_elf_size()
        if elf_size and self.file_analyzer.file_size != elf_size:
            log.warning(
                f"elf weird size: file_size {self.file_analyzer.file_size}({hex(self.file_analyzer.file_size)}), elf_size {elf_size}({hex(elf_size)})"
            )

    def packer_scan(self):
        """
        查壳
        """
        matches = self.get_packer_result()
        if matches:
            self.file_analyzer.packer_list.extend(matches)
            log.info("packer: {}".format(matches))

    def run(self):
        self.elf_size_scan()
        self.packer_scan()
