# coding:utf8

import os
import re
import socket
import requests
from urllib.parse import urlparse

from xanalyzer.utils import log
from xanalyzer.config import Config


class UrlAnalyzer:
    url = None
    parsed_url = None
    main_url = None
    hostname = None
    hostname_type = None
    resolved_ip_list = []

    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.hostname = self.parsed_url.hostname
        self.main_url = f'{self.parsed_url.scheme}://{self.hostname}'
        hostname_type_match = re.match(
            r'^(?:(?P<domain>(?:[-a-zA-Z0-9]+\.)+[a-zA-Z]+)|(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3}))$',
            self.hostname)
        if hostname_type_match:
            self.hostname_type = hostname_type_match.lastgroup
        else:
            self.hostname_type = 'other'
        if self.hostname_type == 'domain':
            self.resolved_ip_list = self.get_ip_list_by_domain(self.hostname)

    @staticmethod
    def get_ip_list_by_domain(domain):
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
        except:
            ip_list = None
        return ip_list

    def get_basic_info(self):
        basic_info = {}
        res = requests.get(self.url)
        status_code = res.status_code
        basic_info['status_code'] = status_code
        if status_code:
            robots_url = f'{self.main_url}/robots.txt'
            robots_res = requests.get(robots_url)
            if robots_res.status_code == 200:
                basic_info['robots_info'] = robots_res.content
        return basic_info

    def basic_scan(self):
        if self.hostname_type == 'domain':
            if self.resolved_ip_list:
                log.info(f'resolved_ip_list: {self.resolved_ip_list}')
            else:
                log.warning('unable to resolve to ip')
        basic_info = self.get_basic_info()
        url_status_code = basic_info.get('status_code', 0)
        if url_status_code:
            log.info(f'url status code: {url_status_code}')
            robots_info = basic_info.get('robots_info', '')
            if robots_info:
                robots_info_len = len(robots_info)
                if robots_info_len == 1:
                    log.info(f'site has robots.txt({len(robots_info)} byte):')
                else:
                    log.info(f'site has robots.txt({len(robots_info)} bytes):')
                if len(robots_info) < 80:
                    log.info(f'    content: {robots_info}')
                else:
                    log.info(f'    80 bytes content: {robots_info[:80]}')
                if Config.conf['save_flag']:
                    robots_data_path = os.path.join(Config.conf['analyze_data_path'], 'robots.txt')
                    with open(robots_data_path, 'wb') as f:
                        f.write(robots_info)
                    log.info('robots.txt saved')

    def run(self):
        self.basic_scan()
