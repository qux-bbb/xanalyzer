# coding:utf8

import requests
from urllib.parse import urlparse

from xanalyzer.utils import log


class UrlAnalyzer:
    url = None
    parsed_url = None
    main_url = None

    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.main_url = f'{self.parsed_url.scheme}://{self.parsed_url.hostname}'

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

    def run(self):
        self.basic_scan()
