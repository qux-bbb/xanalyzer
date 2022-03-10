# coding:utf8

from datetime import datetime
import pefile
import peutils

from signify.authenticode.signed_pe import SignedPEFile

from xanalyzer.config import Config
from xanalyzer.utils import log


class PeAnalyzer:
    file_path = None
    pe_file = None

    def __init__(self, file_path):
        self.file_path = file_path
        self.pe_file = pefile.PE(self.file_path)

    def __del__(self):
        self.pe_file.close()

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
    
    def compile_time_scan(self):
        """
        获取编译时间
        """
        time_str = datetime.fromtimestamp(self.pe_file.FILE_HEADER.TimeDateStamp)
        log.info('compile time: {}'.format(time_str))

    def pdb_scan(self):
        """
        查看pdb路径
        """
        for debug_entry in getattr(self.pe_file, 'DIRECTORY_ENTRY_DEBUG', []):
            if hasattr(debug_entry.entry, 'PdbFileName'):
                log.info('pdb path: {}'.format(debug_entry.entry.PdbFileName.decode('utf8')))
                return

    def versioninfo_scan(self):
        """
        查看pe版本信息
        """
        versioninfo = self.get_versioninfo()
        if versioninfo:
            log.info('versioninfo:')
            for item in versioninfo:
                log.info('    "{}": "{}"'.format(item['name'], item['value']))

    def peid_scan(self):
        """
        查壳
        """
        signatures = peutils.SignatureDatabase(Config.peid_signature_path)
        matches = signatures.match(self.pe_file, ep_only=True)
        if matches:
            log.info(matches)

    def cert_scan(self):
        """
        输出证书信息并验证
        """
        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY) <= security_index:
            return
        security_entry = self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
        if not security_entry.Size or not security_entry.VirtualAddress:
            return
        with open(self.file_path, 'rb') as f:
            try:
                pe = SignedPEFile(f)
                for signed_data in pe.signed_datas:
                    cert = signed_data.certificates[0]
                    log.info('Contains certificates:')
                    log.info('   Subject: {}'.format(cert.subject.dn))
                    log.info('   Issuer: {}'.format(cert.issuer.dn))
                    log.info('   Serial: {}'.format(cert.serial_number))
                    log.info('   Valid from: {}'.format(cert.valid_from))
                    log.info('   Valid to: {}'.format(cert.valid_to))

                    try:
                        signed_data.verify()
                        log.info('Signature: valid')
                    except Exception as e:
                        log.warning('Signature: invalid')
                        log.warning('{}'.format(e))
            except Exception as e:
                log.error('Error while parsing:')
                log.error('{}'.format(e))

    def run(self):
        self.compile_time_scan()
        self.pdb_scan()
        self.versioninfo_scan()
        self.cert_scan()
        self.peid_scan()
