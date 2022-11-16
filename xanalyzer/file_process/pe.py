import re
import pefile
import peutils
from datetime import datetime
from signify.authenticode.signed_pe import SignedPEFile

from xanalyzer.config import Config
from xanalyzer.utils import log


class PeAnalyzer:
    file_analyzer = None
    pe_file = None

    def __init__(self, file_analyzer):
        self.file_analyzer = file_analyzer
        self.pe_file = pefile.PE(self.file_analyzer.file_path)

    def __del__(self):
        self.pe_file.close()

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

        if not hasattr(self.pe_file, "VS_VERSIONINFO") and not hasattr(self.pe_file, "FileInfo"):
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
                                if entry["name"] == b"Translation" and len(entry["value"]) == 10:
                                    entry["value"] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                                versioninfo.append(entry)
                    elif hasattr(entry, "Var"):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, "entry"):
                                entry = {}
                                entry["name"] = list(var_entry.entry.keys())[0].decode()
                                entry["value"] = list(var_entry.entry.values())[0]  # .decode("latin-1")
                                if entry["name"] == b"Translation" and len(entry["value"]) == 10:
                                    entry["value"] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                                versioninfo.append(entry)
                except Exception as e:
                    log.error(e, exc_info=True)
                    continue

        return versioninfo

    def get_compile_time(self):
        compile_time = datetime.fromtimestamp(self.pe_file.FILE_HEADER.TimeDateStamp)
        time_str = str(compile_time)
        return time_str

    def get_pdb_path(self):
        for debug_entry in getattr(self.pe_file, 'DIRECTORY_ENTRY_DEBUG', []):
            if hasattr(debug_entry.entry, 'PdbFileName'):
                return debug_entry.entry.PdbFileName.strip(b'\x00').decode('utf8')
        return

    def get_packer_result(self):
        signatures = peutils.SignatureDatabase(Config.peid_signature_path)
        matches = signatures.match(self.pe_file, ep_only=True)

        if matches:
            return matches

        the_file = open(self.file_analyzer.file_path, 'rb')
        file_content = the_file.read()
        the_file.close()
    
        # Check PyInstaller
        if b'PyInstaller: FormatMessageW failed.' in file_content:
            python_ver_info_s = re.search(rb'(python[0-9.]{2,4})\.dll', file_content)
            if python_ver_info_s:
                python_ver_info = python_ver_info_s.group(1).decode()
                matches = [f'PyInstaller, {python_ver_info}']
            else:
                matches = ['PyInstaller, unknown python version']
            return matches

        return None

    def get_resource_type_dict(self):
        # TODO 通过特殊的id识别icon，改一下数据类型和后缀
        resource_type_dict = {}
        if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE'):
            icon_type_id_list = [
                pefile.RESOURCE_TYPE['RT_ICON'],
                pefile.RESOURCE_TYPE['RT_GROUP_ICON']
            ]
            for resource_entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_entry_id = resource_entry.id
                resource_entry_name = resource_entry.name
                if resource_entry_name:
                    resource_entry_info = f'{resource_entry_id}:{resource_entry_name}'
                else:
                    resource_entry_info = f'{resource_entry_id}'
                for d_entry in resource_entry.directory.entries:
                    d_entry_id = d_entry.id
                    d_entry_name = d_entry.name
                    if d_entry_name:
                        d_entry_info = f'{d_entry_id}:{d_entry_name}'
                    else:
                        d_entry_info = f'{d_entry_id}'
                    for dd_entry in d_entry.directory.entries:
                        dd_entry_id = dd_entry.id
                        dd_entry_name = dd_entry.name
                        if dd_entry_name:
                            dd_entry_info = f'{dd_entry_id}:{dd_entry_name}'
                        else:
                            dd_entry_info = f'{dd_entry_id}'

                        key = f'{resource_entry_info}_{d_entry_info}_{dd_entry_info}'

                        data_rva = dd_entry.data.struct.OffsetToData
                        size = dd_entry.data.struct.Size
                        data = self.pe_file.get_memory_mapped_image()[data_rva:data_rva+size]
                        data_type, possible_extension_names = self.file_analyzer.guess_type_and_ext(data)
                        if (
                            data_type == 'data'
                            and not possible_extension_names
                            and resource_entry_id in icon_type_id_list
                        ):
                            data_type = 'icon'
                            possible_extension_names = ['.ico']
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
        with open(self.file_analyzer.file_path, 'rb') as f:
            try:
                pe = SignedPEFile(f)
                for signed_data in pe.signed_datas:
                    signer_info = signed_data.signer_info
                    signer_serial_number = signer_info.serial_number._value
                    signer_issuer_dn = signer_info.issuer.dn
                    cert = None
                    for tmp_cert in signed_data.certificates:
                        if tmp_cert.serial_number == signer_serial_number and tmp_cert.issuer.dn == signer_issuer_dn:
                            cert = tmp_cert
                            break
                    if cert:
                        cert_info = {}
                        cert_info['subject'] = cert.subject.dn
                        cert_info['issuer'] = cert.issuer.dn
                        cert_info['serial_number'] = cert.serial_number
                        cert_info['signing_time'] = signer_info.signing_time
                        cert_info['valid_from'] = cert.valid_from
                        cert_info['valid_to'] = cert.valid_to

                        try:
                            signed_data.verify()
                            cert_info['verify_result'] = 'valid'
                        except Exception as e:
                            cert_info['verify_result'] = 'invalid: {}'.format(e)
                        cert_info_list.append(cert_info)
            except Exception as e:
                log.error('Error while parsing:')
                log.error('{}'.format(e))
        return cert_info_list

    def pe_size_scan(self):
        """
        判断文件大小是否和纯PE匹配，是否有多余数据
        因为是PE的特殊情况，不考虑和文件大小放在一起
        """
        pe_size = self.get_pe_size()
        if pe_size and self.file_analyzer.file_size != pe_size:
            log.warning(f'pe weird size: file_size {self.file_analyzer.file_size}({hex(self.file_analyzer.file_size)}), pe_size {pe_size}({hex(pe_size)})')

    def compile_time_scan(self):
        """
        查看编译时间
        """
        time_str = self.get_compile_time()
        if time_str:
            log.info('compile time: {}'.format(time_str))

    def pdb_scan(self):
        """
        查看pdb路径
        """
        pdb_path = self.get_pdb_path()
        if pdb_path:
            log.info('pdb path: {}'.format(pdb_path))

    def versioninfo_scan(self):
        """
        查看pe版本信息
        """
        versioninfo = self.get_versioninfo()
        if versioninfo:
            log.info('versioninfo:')
            for item in versioninfo:
                log.info('    "{}": "{}"'.format(item['name'], item['value']))

    def section_name_scan(self):
        """
        输出节区名
        """
        section_names = []
        for section in self.pe_file.sections:
            section_names.append(section.Name.strip(b'\x00'))
        log.info(f'section names: {section_names}')

    def packer_scan(self):
        """
        查壳
        """
        matches = self.get_packer_result()
        if matches:
            self.file_analyzer.packer_list.extend(matches)
            log.info('packer: {}'.format(matches))

    def cert_scan(self):
        """
        输出证书信息并验证
        """
        cert_info_list = self.verify_cert()
        if cert_info_list:
            log.info('contains certificates:')
            for cert_info in cert_info_list:
                log.info('   Subject: {}'.format(cert_info.get('subject', '')))
                log.info('   Issuer: {}'.format(cert_info.get('issuer', '')))
                log.info('   Serial number: {}'.format(cert_info.get('serial_number', '')))
                # TODO signify的signing_time大概率获取不到，暂时判断有值再输出
                signing_time = cert_info.get('signing_time', '')
                if signing_time:
                    log.info('   signing time: {}'.format(signing_time))
                log.info('   Valid from: {}'.format(cert_info.get('valid_from', '')))
                log.info('   Valid to: {}'.format(cert_info.get('valid_to', '')))
                verify_result = cert_info.get('verify_result', '')
                if verify_result == 'valid':
                    log.info('   Verify result: {}'.format(verify_result))
                else:
                    log.warning('   Verify result: {}'.format(verify_result))

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
                if possible_extension_name in ['.exe', '.dll', '.sys']:
                    weird_resource_type_set.add(possible_extension_name)
        self.file_analyzer.pe_resource_type_list = list(resource_type_set)
        weird_resource_type_list = list(weird_resource_type_set)
        if weird_resource_type_list:
            log.warning(f'pe weird resource type: {weird_resource_type_list}')

    def run(self):
        self.pe_size_scan()
        self.compile_time_scan()
        self.pdb_scan()
        self.versioninfo_scan()
        self.cert_scan()
        self.section_name_scan()
        self.packer_scan()
        self.resource_scan()
