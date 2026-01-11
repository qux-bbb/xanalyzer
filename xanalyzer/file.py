import io
import json
import os
import re
from hashlib import md5, sha256
from pathlib import Path
from zipfile import ZipFile

import magic
import yara

from xanalyzer.config import Config
from xanalyzer.file_process.elf import ElfAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer
from xanalyzer.file_process.jpg import JpgAnalyzer
from xanalyzer.utils import log


class FileAnalyzer:
    packer_yara_rules = None

    def __init__(self, file_path, minstrlen=4):
        self.file_path = file_path
        self.file_size = os.path.getsize(self.file_path)
        the_file = open(self.file_path, "rb")
        the_content = the_file.read()
        the_file.close()
        self.file_type, self.possible_extension_names = self.guess_type_and_ext(
            the_content
        )

        minstrlen_bytes = str(minstrlen).encode()
        self.str_re = re.compile(rb"[\x20-\x7e]{"+minstrlen_bytes+rb",}")
        self.wide_str_re = re.compile(rb"(?:[\x20-\x7e]\x00){"+minstrlen_bytes+rb",}")

        self.packer_list = []
        self.pe_resource_type_list = []
        self.pe_versioninfo = []

        self.init_packer_yara_rules()

    @classmethod
    def init_packer_yara_rules(cls):
        if cls.packer_yara_rules:
            return
        yara_filenames = os.listdir(Config.packer_yara_rules_path)
        yara_dict = {}
        for yara_filename in yara_filenames:
            yara_path = os.path.join(Config.packer_yara_rules_path, yara_filename)
            yara_dict[yara_filename] = yara_path
        cls.packer_yara_rules = yara.compile(filepaths=yara_dict)

    def packer_yara_match(self):
        the_file = open(self.file_path, "rb")
        the_content = the_file.read()
        the_file.close()
        return self.packer_yara_rules.match(data=the_content)

    def guess_type_and_ext(self, the_content):
        """
        猜测文件类型和扩展名
        :return: file_type, possible_extension_names
        """
        # magic.from_file不能通过中文路径读取文件，暂时使用magic.from_buffer
        the_file_type = magic.from_buffer(the_content)
        the_ext = []
        if the_file_type.startswith("Zip archive data"):
            the_file = io.BytesIO(the_content)
            the_zip = ZipFile(the_file)
            zip_namelist = the_zip.namelist()
            the_zip.close()
            if "AndroidManifest.xml" in zip_namelist:
                the_file_type = f"{the_file_type}, APK(Android application package)"
            elif "[Content_Types].xml" in zip_namelist:
                if "word/document.xml" in zip_namelist:
                    the_file_type = "Microsoft Word 2007+"
                elif "xl/workbook.xml" in zip_namelist:
                    the_file_type = "Microsoft Excel 2007+"
                elif "ppt/presentation.xml" in zip_namelist:
                    the_file_type = "Microsoft PowerPoint 2007+"

        if the_file_type.startswith("Composite Document File V2 Document"):
            if "MSI Installer" in the_file_type:
                the_ext = [".msi"]
            elif "WordDocument".encode("utf_16_le") in the_content:
                if "Name of Creating Application: WPS" in the_file_type:
                    the_ext = [".doc", ".wps"]
                else:
                    the_ext = [".doc"]
            elif "Workbook".encode("utf_16_le") in the_content:
                if "Name of Creating Application: WPS" in the_file_type:
                    the_ext = [".xls", ".et"]
                else:
                    the_ext = [".xls"]
            elif "PowerPoint Document".encode("utf_16_le") in the_content:
                if "Name of Creating Application: WPS" in the_file_type:
                    the_ext = [".ppt", ".dps"]
                else:
                    the_ext = [".ppt"]

        if the_file_type.startswith(
            ("PE32+ executable (DLL)", "PE32 executable (DLL)")
        ):
            the_ext = [".dll"]
        elif the_file_type.startswith(
            ("PE32+ executable (native)", "PE32 executable (native)")
        ):
            the_ext = [".sys"]
        elif the_file_type.startswith(
            ("PE32+ executable", "PE32 executable", "MS-DOS executable")
        ):
            the_ext = [".exe"]
        elif the_file_type.startswith("PDF document"):
            the_ext = [".pdf"]
        elif the_file_type == "Microsoft Word 2007+":
            the_ext = [".docx"]
        elif the_file_type == "Microsoft Excel 2007+":
            the_ext = [".xlsx"]
        elif the_file_type == "Microsoft PowerPoint 2007+":
            the_ext = [".pptx"]
        elif the_file_type.startswith("Zip archive data"):
            if "APK(Android application package)" in the_file_type:
                the_ext = [".apk"]
            else:
                the_ext = [".zip"]
        elif the_file_type.startswith("7-zip archive data"):
            the_ext = [".7z"]
        elif the_file_type.startswith("RAR archive data"):
            the_ext = [".rar"]
        elif the_file_type.startswith("gzip compressed data"):
            the_ext = [".gz", ".tar.gz"]
        elif the_file_type.startswith("PNG image data"):
            the_ext = [".png"]
        elif the_file_type.startswith("JPEG image data"):
            the_ext = [".jpg"]
        elif the_file_type.startswith("PC bitmap"):
            the_ext = [".bmp"]
        elif the_file_type.startswith("GIF image data"):
            the_ext = [".gif"]
        elif the_file_type.startswith("Audio file with ID3"):
            the_ext = [".mp3"]
        elif the_file_type.startswith("ISO Media, MP4 Base Media"):
            the_ext = [".mp4"]
        elif the_file_type.startswith("Macromedia Flash Video"):
            the_ext = [".flv"]
        elif the_file_type.startswith("RIFF (little-endian) data, AVI"):
            the_ext = [".avi"]
        elif the_file_type.startswith(("ASCII text", "UTF-8 Unicode text")):
            the_ext = [".txt"]
        elif the_file_type.startswith("tcpdump capture file"):
            the_ext = [".pcap"]
        elif the_file_type.startswith("pcap-ng capture file"):
            the_ext = [".pcapng"]
        elif the_file_type.startswith(
            ("Bourne-Again shell script", "POSIX shell script")
        ):
            the_ext = [".sh"]

        return the_file_type, the_ext

    @staticmethod
    def get_windows_style_file_size(tmp_size):
        """
        得到windows风格的文件大小展示
        参考: https://stackoverflow.com/a/1094933/7164926
        [0, 1024字节): 直接展示size
        [1024字节, 1000YB):
            如果整数位数大于3，则以下一单位计数；
            如果整数位数为3，保留整数位置，有小数则略去；
            如果整数位数小于3，以小数展示
                小数展示规则：整数位数和小数位数加起来共3位显示(不包括小数点)，后面数字略去
        [1000YB, +): 直接展示size
        """
        if tmp_size == 0:
            return "0 字节"

        bytes_size = " ({} 字节)".format(format(tmp_size, ","))
        if tmp_size < 1024:
            return f"{tmp_size} 字节{bytes_size}"
        tmp_formatted_size = 0
        tmp_unit = ""
        for unit in ["字节", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"]:
            if abs(tmp_size) < 1000.0:
                tmp_formatted_size = tmp_size
                tmp_unit = unit
                break
            tmp_size /= 1024.0
        else:
            tmp_formatted_size = tmp_size
            tmp_unit = "YB"

        if tmp_unit == "YB" and tmp_formatted_size >= 1000:
            return f"{tmp_formatted_size} YB{bytes_size}"

        tmp_formatted_size = str(tmp_formatted_size)
        if "." in tmp_formatted_size[:3]:
            formatted_size = "{:0<4}".format(tmp_formatted_size[:4])
        else:
            formatted_size = tmp_formatted_size[:3]

        return f"{formatted_size} {tmp_unit}{bytes_size}"

    def get_md5_sha256(self):
        the_file = open(self.file_path, "rb")
        file_content = the_file.read()
        the_file.close()
        md5_value = md5(file_content).hexdigest()
        sha256_value = sha256(file_content).hexdigest()
        return (md5_value, sha256_value)

    def get_strs(self):
        the_file = open(self.file_path, "rb")
        file_content = the_file.read()
        the_file.close()
        all_strs = re.findall(self.str_re, file_content)
        return all_strs

    def get_wide_strs(self):
        the_file = open(self.file_path, "rb")
        file_content = the_file.read()
        the_file.close()
        all_strs = re.findall(self.wide_str_re, file_content)
        return all_strs

    def get_special_strs(self):
        the_file = open(self.file_path, "rb")
        file_content = the_file.read()
        the_file.close()
        tmp_base64_strs = re.findall(rb"[A-Za-z0-9+/]{14,}={0,2}", file_content)
        possible_base64_strs = []
        for tmp_base64_str in tmp_base64_strs:
            # 过滤hex字符串
            if re.match(rb"(?:[A-Fa-f0-9]{2}){4,}", tmp_base64_str):
                continue
            possible_base64_strs.append(tmp_base64_str)
        hex_strs = re.findall(rb"(?:[A-Fa-f0-9]{2}){4,}", file_content)
        special_strs = possible_base64_strs + hex_strs
        return special_strs

    def get_special_wide_strs(self):
        the_file = open(self.file_path, "rb")
        file_content = the_file.read()
        the_file.close()
        tmp_base64_strs = re.findall(
            rb"(?:[A-Za-z0-9+/]\x00){14,}(?:=\x00){0,2}",
            file_content,
        )
        possible_base64_strs = []
        for tmp_base64_str in tmp_base64_strs:
            # 过滤hex字符串
            if re.match(rb"(?:(?:[A-Fa-f0-9]\x00){2}){4,}", tmp_base64_str):
                continue
            possible_base64_strs.append(tmp_base64_str)
        hex_strs = re.findall(rb"(?:(?:[A-Fa-f0-9]\x00){2}){4,}", file_content)
        special_wide_strs = possible_base64_strs + hex_strs
        return special_wide_strs

    def get_tool_recommendations(self):
        recommended_tool_names = []

        if self.file_type.startswith(("PE", "MS-DOS executable")):
            recommended_tool_names.append("XPEViewer")

            for item in self.pe_versioninfo:
                if (
                    item["name"] == "Comments"
                    and item["value"] == "This installation was built with Inno Setup."
                ):
                    recommended_tool_names.append("Innounp")
                    break

            if "Mono/.Net assembly" in self.file_type:
                recommended_tool_names.append("dnSpy")

            if "Nullsoft Installer" in self.file_type:
                recommended_tool_names.append("7z-build-nsis")

            for extension in [
                ".ico",
                ".png",
                ".jpg",
                ".bmp",
                ".gif",
                ".exe",
                ".dll",
                ".sys",
            ]:
                if extension in self.pe_resource_type_list:
                    recommended_tool_names.append("Resource Hacker")
                    break
        elif self.file_type.startswith("ELF"):
            recommended_tool_names.append("XELFViewer")
        elif "APK(Android application package)" in self.file_type:
            recommended_tool_names.append("JADX")
        elif "Name of Creating Application: WPS" in self.file_type:
            recommended_tool_names.append("WPS Office")
        elif (
            "Microsoft Word 2007+" == self.file_type
            or "Name of Creating Application: Microsoft Office Word" in self.file_type
        ):
            recommended_tool_names.append("Microsoft Office Word")
        elif (
            "Microsoft Excel 2007+" == self.file_type
            or "Name of Creating Application: Microsoft Office Excel" in self.file_type
        ):
            recommended_tool_names.append("Microsoft Office Excel")
        elif (
            "Microsoft PowerPoint 2007+" == self.file_type
            or "Name of Creating Application: Microsoft Office PowerPoint"
            in self.file_type
        ):
            recommended_tool_names.append("Microsoft Office PowerPoint")
        elif self.file_type.startswith(
            ("tcpdump capture file", "pcap-ng capture file")
        ):
            recommended_tool_names.extend(["Wireshark", "BruteShark"])

        for packer in self.packer_list:
            if packer.startswith("UPX "):
                recommended_tool_names.append("UPX")
            if packer.startswith("PyInstaller,"):
                recommended_tool_names.append("PyInstaller Extractor")

        if ".xls" in self.possible_extension_names:
            recommended_tool_names.append("oletools")
        elif ".msi" in self.possible_extension_names:
            recommended_tool_names.append("lessmsi")

        with open(Config.tools_info_path, "r") as f:
            tools_info = json.load(f)
        recommended_tool_info_list = []
        for recommended_tool_name in recommended_tool_names:
            recommended_tool_info_list.append(
                f"{recommended_tool_name}: {tools_info.get(recommended_tool_name)}"
            )
        return recommended_tool_info_list

    def str_scan(self):
        all_strs = self.get_strs()
        if all_strs:
            log.info(f"str num: {len(all_strs)}")
            if Config.conf["save_flag"]:
                str_file_name = Path(self.file_path).name + "_strings.txt"
                str_data_path = os.path.join(
                    Config.conf["analyze_data_path"], str_file_name
                )
                with open(str_data_path, "wb") as f:
                    for a_str in all_strs:
                        f.write(a_str + b"\n")
                log.info(f"{str_file_name} saved")

        all_wide_strs = self.get_wide_strs()
        if all_wide_strs:
            log.info(f"wide str num: {len(all_wide_strs)}")
            if Config.conf["save_flag"]:
                wide_str_file_name = Path(self.file_path).name + "_wide_strings.txt"
                wide_str_data_path = os.path.join(
                    Config.conf["analyze_data_path"], wide_str_file_name
                )
                with open(wide_str_data_path, "wb") as f:
                    for a_str in all_wide_strs:
                        f.write(a_str + b"\n\x00")
                log.info(f"{wide_str_file_name} saved")

                wide_to_normal_str_file_name = (
                    Path(self.file_path).name + "_wide_to_normal_strings.txt"
                )
                wide_to_normal_str_data_path = os.path.join(
                    Config.conf["analyze_data_path"], wide_to_normal_str_file_name
                )
                with open(wide_to_normal_str_data_path, "wb") as f:
                    for a_str in all_wide_strs:
                        normal_str = a_str.replace(b"\x00", b"")
                        f.write(normal_str + b"\n")
                log.info(f"{wide_to_normal_str_file_name} saved")

        special_strs = self.get_special_strs()
        if special_strs:
            log.info(f"special strs num: {len(special_strs)}")
            if Config.conf["save_flag"]:
                special_str_file_name = (
                    Path(self.file_path).name + "_special_strings.txt"
                )
                str_data_path = os.path.join(
                    Config.conf["analyze_data_path"], special_str_file_name
                )
                with open(str_data_path, "wb") as f:
                    for a_str in special_strs:
                        f.write(a_str + b"\n")
                log.info(f"{special_str_file_name} saved")

        special_wide_strs = self.get_special_wide_strs()
        if special_wide_strs:
            log.info(f"special wide str num: {len(special_wide_strs)}")
            if Config.conf["save_flag"]:
                special_wide_str_file_name = (
                    Path(self.file_path).name + "_special_wide_strings.txt"
                )
                special_wide_str_data_path = os.path.join(
                    Config.conf["analyze_data_path"], special_wide_str_file_name
                )
                with open(special_wide_str_data_path, "wb") as f:
                    for a_str in special_wide_strs:
                        f.write(a_str + b"\n\x00")
                log.info(f"{special_wide_str_file_name} saved")

    def tool_recommendations_scan(self):
        recommended_tool_info_list = self.get_tool_recommendations()
        if recommended_tool_info_list:
            log.info("recommended tool info:")
            for recommended_tool_info in recommended_tool_info_list:
                log.info(f"    {recommended_tool_info}")

    def run(self):
        md5_value, sha256_value = self.get_md5_sha256()
        log.info("md5: {}".format(md5_value))
        log.info("sha256: {}".format(sha256_value))
        log.info("file type: {}".format(self.file_type))
        log.info("possible extension names: {}".format(self.possible_extension_names))
        log.info("file size: {}({})".format(self.file_size, hex(self.file_size)))
        log.info(
            "windows style file size: {}".format(
                self.get_windows_style_file_size(self.file_size)
            )
        )

        self.str_scan()

        if self.file_type.startswith(("PE", "MS-DOS executable")):
            # 把自身传入，让PeAnalyzer可以使用和修改FileAnalyzer实例(属性和方法)
            pe_analyzer = PeAnalyzer(self)
            pe_analyzer.run()
        elif self.file_type.startswith("ELF"):
            elf_analyzer = ElfAnalyzer(self)
            elf_analyzer.run()
        elif self.file_type.startswith("JPEG image data"):
            jpg_analyzer = JpgAnalyzer(self)
            jpg_analyzer.run()

        self.tool_recommendations_scan()
