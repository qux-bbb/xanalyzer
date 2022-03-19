# coding:utf8

import os
import re
import socket
import requests
from urllib.parse import urlparse, urljoin

from xanalyzer.utils import log
from xanalyzer.config import Config


class UrlAnalyzer:
    url = None
    parsed_url = None
    main_url = None
    hostname = None
    hostname_type = None
    resolved_ip_list = []
    links = []

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

    def link_scan(self):
        """
        扫描站点内所有链接，结果太多，暂不启用
        """
        links_file_name = 'url_links.txt'
        if Config.conf['save_flag']:
            links_file_path = os.path.join(Config.conf['analyze_data_path'], links_file_name)
        ignore_tails = ('.jpg', '.png', '.gif', '.ico', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', 'pptx', '.apk', '.wav', '.zip', '.rar', '.7z')

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
            "Referer": "http://www.google.com",
        }

        self.links.append(self.main_url)
        links_to_req = [self.main_url]

        for link in links_to_req:
            try:
                res = requests.get(link, headers=headers)
            except Exception as e:
                log.error(f'{e.__class__} {link}')

            # 只处理文本形式的响应
            if 'text/' not in res.headers.get('Content-Type', ''):
                continue

            half_links = re.findall(rb'(?:href|src|action)\s?=\s?"(.*?)"', res.content)
            half_links.extend(re.findall(rb"(?:href|src|action)\s?=\s?\'(.*?)\'", res.content))

            for half_link in half_links:
                half_link = half_link.decode()
                joined_link = urljoin(res.url, half_link)

                if joined_link not in self.links:
                    self.links.append(joined_link)
                    if Config.conf['save_flag']:
                        with open(links_file_path, 'a') as f:
                            f.write(f'{link}\n')
                # 链接在本站下、不是资源链接、不在待请求列表里，则添加到待请求列表
                if self.hostname in joined_link\
                        and not joined_link.endswith(ignore_tails)\
                        and joined_link not in links_to_req:
                    links_to_req.append(joined_link)

    def run(self):
        self.basic_scan()
        # self.link_scan()
