import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pefile
import peutils
from signify.authenticode.signed_pe import SignedPEFile

from xanalyzer.config import Config
from xanalyzer.utils import log


class PeAnalyzer:
    file_analyzer = None
    pe_file = None
    peid_signatures = None

    def __init__(self, file_analyzer):
        self.file_analyzer = file_analyzer
        self.pe_file = pefile.PE(self.file_analyzer.file_path)

        self.init_peid_signatures()

    def __del__(self):
        self.pe_file.close()

    @classmethod
    def init_peid_signatures(cls):
        if cls.peid_signatures:
            return
        cls.peid_signatures = peutils.SignatureDatabase(Config.peid_signature_path)

    def get_pe_size(self):
        """
        计算真实PE大小
        """
        if not self.pe_file.sections:
            return

        pe_size = 0

        # 考虑有证书的情况
        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY) > security_index:
            security_entry = self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
            if security_entry.Size and security_entry.VirtualAddress:
                pe_size = security_entry.VirtualAddress + security_entry.Size

        if not pe_size:
            last_section = self.pe_file.sections[-1]
            pe_size = last_section.PointerToRawData + last_section.SizeOfRawData

        return pe_size

    def get_versioninfo(self):
        """Get version info.
        @return: info dict or None.
        code from CAPEv2
        """
        if not self.pe_file:
            return None

        versioninfo = []

        if not hasattr(self.pe_file, "VS_VERSIONINFO") and not hasattr(
            self.pe_file, "FileInfo"
        ):
            return versioninfo

        for info_entry in self.pe_file.FileInfo:
            for entry in info_entry:
                try:
                    if hasattr(entry, "StringTable"):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                entry = {}
                                entry["name"] = str_entry[0].decode()
                                entry["value"] = str_entry[1].decode()
                                if (
                                    entry["name"] == b"Translation"
                                    and len(entry["value"]) == 10
                                ):
                                    entry[
                                        "value"
                                    ] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                                versioninfo.append(entry)
                    elif hasattr(entry, "Var"):
                        for var_entry in entry.Var:
                            if not hasattr(var_entry, "entry"):
                                continue
                            entry = {}
                            entry["name"] = list(var_entry.entry.keys())[0].decode()
                            entry["value"] = list(var_entry.entry.values())[0]
                            if (
                                entry["name"] == b"Translation"
                                and len(entry["value"]) == 10
                            ):
                                entry[
                                    "value"
                                ] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                            versioninfo.append(entry)
                except Exception as e:
                    log.error(e, exc_info=True)
                    continue

        return versioninfo

    def get_compile_time(self):
        compile_time = datetime.fromtimestamp(
            self.pe_file.FILE_HEADER.TimeDateStamp, tz=timezone.utc
        )
        time_str = compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        return time_str

    def get_pdb_path(self):
        for debug_entry in getattr(self.pe_file, "DIRECTORY_ENTRY_DEBUG", []):
            if hasattr(debug_entry.entry, "PdbFileName"):
                return debug_entry.entry.PdbFileName.strip(b"\x00").decode("utf8")
        return

    def get_dll_name(self):
        if self.file_analyzer.possible_extension_names != [".dll"]:
            return
        if hasattr(self.pe_file, "DIRECTORY_ENTRY_EXPORT"):
            return self.pe_file.DIRECTORY_ENTRY_EXPORT.name
        return

    def get_exe_import_api_list(self, lower_flag=False):
        exe_import_api_list = []
        if not hasattr(self.pe_file, "DIRECTORY_ENTRY_IMPORT"):
            return []
        directory_entry_import = self.pe_file.DIRECTORY_ENTRY_IMPORT
        for entry_import in directory_entry_import:
            dll_name = entry_import.dll.decode()
            dll_base_name = dll_name
            if dll_name.lower().endswith(".dll"):
                dll_base_name = dll_name[:-4]
            for the_api in entry_import.imports:
                # cbb16b01a8dcf3747a597ceb4176939f83083a6293b60aaca00e040970d63379 the_api.name有None的情况
                if hasattr(the_api, "name") and the_api.name:
                    api_name = the_api.name.decode()
                    item_name = f"{dll_base_name}.{api_name}"
                    if lower_flag:
                        item_name = item_name.lower()
                    exe_import_api_list.append(item_name)
        return exe_import_api_list

    def get_packer_result(self):
        matches = self.peid_signatures.match(self.pe_file, ep_only=True)

        if not matches:
            yara_matches = self.file_analyzer.packer_yara_match()
            if yara_matches:
                matches = []
                for yara_match in yara_matches:
                    matches.append(yara_match.rule)

        if matches:
            for i in range(len(matches)):
                if matches[i].startswith("UPX"):
                    the_file = open(self.file_analyzer.file_path, "rb")
                    file_content = the_file.read()
                    the_file.close()
                    upx_ver_s = re.search(rb"(\d+\.\d+)\x00UPX!", file_content)
                    if upx_ver_s:
                        matches[i] = f"UPX {upx_ver_s.group(1).decode()}"
                    break
            return matches

        the_file = open(self.file_analyzer.file_path, "rb")
        file_content = the_file.read()
        the_file.close()

        # Check PyInstaller
        if b"PyInstaller: FormatMessageW failed." in file_content:
            python_ver_info_s = re.search(rb"(python[0-9.]{2,4})\.dll", file_content)
            if python_ver_info_s:
                python_ver_info = python_ver_info_s.group(1).decode()
                matches = [f"PyInstaller, {python_ver_info}"]
            else:
                matches = ["PyInstaller, unknown python version"]
            return matches

        return None

    def get_resource_type_dict(self):
        resource_type_dict = {}
        if not hasattr(self.pe_file, "DIRECTORY_ENTRY_RESOURCE"):
            return resource_type_dict

        icon_type_id_list = [
            pefile.RESOURCE_TYPE["RT_ICON"],
            pefile.RESOURCE_TYPE["RT_GROUP_ICON"],
        ]
        for resource_entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
            resource_entry_id = resource_entry.id
            resource_entry_name = resource_entry.name
            if resource_entry_name:
                resource_entry_info = f"{resource_entry_id}:{resource_entry_name}"
            else:
                resource_entry_info = f"{resource_entry_id}"
            for d_entry in resource_entry.directory.entries:
                d_entry_id = d_entry.id
                d_entry_name = d_entry.name
                if d_entry_name:
                    d_entry_info = f"{d_entry_id}:{d_entry_name}"
                else:
                    d_entry_info = f"{d_entry_id}"
                for dd_entry in d_entry.directory.entries:
                    dd_entry_id = dd_entry.id
                    dd_entry_name = dd_entry.name
                    if dd_entry_name:
                        dd_entry_info = f"{dd_entry_id}:{dd_entry_name}"
                    else:
                        dd_entry_info = f"{dd_entry_id}"

                    key = f"{resource_entry_info}_{d_entry_info}_{dd_entry_info}"

                    data_rva = dd_entry.data.struct.OffsetToData
                    size = dd_entry.data.struct.Size
                    data = self.pe_file.get_memory_mapped_image()[
                        data_rva : data_rva + size
                    ]
                    (
                        data_type,
                        possible_extension_names,
                    ) = self.file_analyzer.guess_type_and_ext(data)
                    if (
                        data_type == "data"
                        and not possible_extension_names
                        and resource_entry_id in icon_type_id_list
                    ):
                        data_type = "icon"
                        possible_extension_names = [".ico"]
                    resource_type_dict[key] = [data_type, possible_extension_names]
        return resource_type_dict

    def verify_cert(self):
        cert_info_list = []
        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY) <= security_index:
            return
        security_entry = self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
        if not security_entry.Size or not security_entry.VirtualAddress:
            return
        pe_file = open(self.file_analyzer.file_path, "rb")
        try:
            pe = SignedPEFile(pe_file)
            for signed_data in pe.signed_datas:
                signer_info = signed_data.signer_info
                signer_serial_number = signer_info.serial_number._value
                signer_issuer_dn = signer_info.issuer.dn
                cert = None
                for tmp_cert in signed_data.certificates:
                    if (
                        tmp_cert.serial_number == signer_serial_number
                        and tmp_cert.issuer.dn == signer_issuer_dn
                    ):
                        cert = tmp_cert
                        break
                if not cert:
                    continue

                cert_info = {}
                cert_info["subject"] = cert.subject.dn
                cert_info["issuer"] = cert.issuer.dn
                cert_info["serial_number"] = cert.serial_number
                cert_info["signing_time"] = signer_info.signing_time
                cert_info["valid_from"] = cert.valid_from
                cert_info["valid_to"] = cert.valid_to

                try:
                    signed_data.verify()
                    cert_info["verify_result"] = "valid"
                except Exception as e:
                    cert_info["verify_result"] = "invalid: {}".format(e)
                cert_info_list.append(cert_info)
        except Exception as e:
            log.error("Error while parsing:")
            log.error("{}".format(e))
        pe_file.close()
        return cert_info_list

    def pe_size_scan(self):
        """
        判断文件大小是否和纯PE匹配，是否有多余数据
        因为是PE的特殊情况，不考虑和文件大小放在一起
        """
        pe_size = self.get_pe_size()
        if pe_size and self.file_analyzer.file_size != pe_size:
            log.warning(
                f"pe weird size: file_size {self.file_analyzer.file_size}({hex(self.file_analyzer.file_size)}), pe_size {pe_size}({hex(pe_size)})"
            )
            if pe_size < self.file_analyzer.file_size and Config.conf["save_flag"]:
                the_file = open(self.file_analyzer.file_path, "rb")
                the_content = the_file.read()
                the_file.close()

                stripped_file_name = Path(self.file_analyzer.file_path).name + "_stripped"
                stripped_file_path = os.path.join(
                    Config.conf["analyze_data_path"], stripped_file_name
                )
                with open(stripped_file_path, "wb") as f:
                    f.write(the_content[:pe_size])
                log.info(f"{stripped_file_name} saved")

                appended_file_name = Path(self.file_analyzer.file_path).name + "_appended_data"
                appended_file_path = os.path.join(
                    Config.conf["analyze_data_path"], appended_file_name
                )
                with open(appended_file_path, "wb") as f:
                    f.write(the_content[pe_size:])
                log.info(f"{appended_file_name} saved")

    def compile_time_scan(self):
        """
        查看编译时间
        """
        time_str = self.get_compile_time()
        if time_str:
            log.info("compile time: {}".format(time_str))

    def pdb_scan(self):
        """
        查看pdb路径
        """
        pdb_path = self.get_pdb_path()
        if pdb_path:
            log.info("pdb path: {}".format(pdb_path))

    def versioninfo_scan(self):
        """
        查看pe版本信息
        """
        versioninfo = self.get_versioninfo()
        if versioninfo:
            self.file_analyzer.pe_versioninfo = versioninfo
            log.info("versioninfo:")
            for item in versioninfo:
                log.info('    "{}": "{}"'.format(item["name"], item["value"]))

    def section_name_scan(self):
        """
        输出节区名
        """
        section_names = []
        for section in self.pe_file.sections:
            section_names.append(section.Name.strip(b"\x00"))
        log.info(f"section names: {section_names}")

    def dll_name_scan(self):
        """
        如果是dll，尝试输出dll名称
        """
        dll_name = self.get_dll_name()
        if dll_name:
            log.info(f"dll name: {dll_name}")

    def packer_scan(self):
        """
        查壳
        """
        matches = self.get_packer_result()
        if matches:
            self.file_analyzer.packer_list.extend(matches)
            log.info("packer: {}".format(matches))

    def cert_scan(self):
        """
        输出证书信息并验证
        """
        cert_info_list = self.verify_cert()
        if cert_info_list:
            log.info("contains certificates:")
            for cert_info in cert_info_list:
                log.info("    Subject: {}".format(cert_info.get("subject", "")))
                log.info("    Issuer: {}".format(cert_info.get("issuer", "")))
                log.info(
                    "    Serial number: {}".format(cert_info.get("serial_number", ""))
                )
                # TODO signify的signing_time大概率获取不到，暂时判断有值再输出
                # 可使用该文件测试 tests/test_data/java.exe_
                signing_time = cert_info.get("signing_time", "")
                if signing_time:
                    log.info("    Signing time: {}".format(signing_time))
                else:
                    log.warning("    Can not get signing time, please view it manually")
                log.info("    Valid from: {}".format(cert_info.get("valid_from", "")))
                log.info("    Valid to: {}".format(cert_info.get("valid_to", "")))
                verify_result = cert_info.get("verify_result", "")
                if verify_result == "valid":
                    log.info("    Verify result: {}".format(verify_result))
                else:
                    log.warning("    Verify result: {}".format(verify_result))

    def exe_import_api_scan(self):
        if self.file_analyzer.possible_extension_names != [".exe"]:
            return
        exe_import_api_list = self.get_exe_import_api_list(lower_flag=True)
        api_num = len(exe_import_api_list)
        if api_num == 0:
            log.warning("the exe does not have import api")
        elif api_num == 1:
            the_api = exe_import_api_list[0]
            if the_api.startswith("kernel32.loadlibrary"):
                log.warning(f"the exe only has 1 import api: {the_api}")
        elif api_num == 2:
            if "kernel32.getprocaddress" in exe_import_api_list:
                warning_flag = False
                for the_api in exe_import_api_list:
                    if the_api != "kernel32.getprocaddress" and the_api.startswith("kernel32.loadlibrary"):
                        warning_flag = True
                        break
                if warning_flag:
                    log.warning(f"the exe only has 2 import api: {exe_import_api_list}")

    def resource_scan(self):
        """
        检查资源类型
        """
        resource_type_dict = self.get_resource_type_dict()
        resource_type_set = set()
        weird_resource_type_set = set()
        for data_type, possible_extension_names in resource_type_dict.values():
            for possible_extension_name in possible_extension_names:
                resource_type_set.add(possible_extension_name)
                if possible_extension_name in [".exe", ".dll", ".sys"]:
                    weird_resource_type_set.add(possible_extension_name)
        self.file_analyzer.pe_resource_type_list = list(resource_type_set)
        weird_resource_type_list = list(weird_resource_type_set)
        if weird_resource_type_list:
            log.warning(f"pe weird resource type: {weird_resource_type_list}")

    def run(self):
        self.pe_size_scan()
        self.compile_time_scan()
        self.pdb_scan()
        self.versioninfo_scan()
        self.cert_scan()
        self.section_name_scan()
        self.dll_name_scan()
        self.packer_scan()
        self.exe_import_api_scan()
        self.resource_scan()
