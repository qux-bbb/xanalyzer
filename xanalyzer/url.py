import os
import re
import socket
from urllib.parse import urljoin, urlparse

import requests

from xanalyzer.config import Config
from xanalyzer.utils import log


class UrlAnalyzer:
    url = None
    parsed_url = None
    main_url = None
    hostname = None
    hostname_type = None
    resolved_ip_list = []
    links = []
    basic_domain = None
    subdomain_list = []

    def __init__(self, url, deep_flag):
        self.url = url
        self.deep_flag = deep_flag
        self.parsed_url = urlparse(url)
        self.hostname = self.parsed_url.hostname
        self.main_url = f"{self.parsed_url.scheme}://{self.hostname}"
        hostname_type_match = re.match(
            r"^(?:(?P<domain>(?:[-a-zA-Z0-9]+\.)+[a-zA-Z]+)|(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3}))$",
            self.hostname,
        )
        if hostname_type_match:
            self.hostname_type = hostname_type_match.lastgroup
        else:
            self.hostname_type = "other"
        if self.hostname_type == "domain":
            self.resolved_ip_list = self.get_ip_list_by_domain(self.hostname)
            self.basic_domain = re.search(
                r"[-a-zA-Z0-9]+\.[a-zA-Z]+$", self.hostname
            ).group()

    @staticmethod
    def get_ip_list_by_domain(domain):
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
        except:
            ip_list = None
        return ip_list

    def get_basic_info(self):
        """
        获取状态码和robots.txt信息
        """
        basic_info = {}
        res = requests.get(self.url)
        status_code = res.status_code
        basic_info["status_code"] = status_code
        if status_code:
            robots_url = f"{self.main_url}/robots.txt"
            robots_res = requests.get(robots_url)
            if robots_res.status_code == 200:
                basic_info["robots_info"] = robots_res.content
        return basic_info

    def basic_scan(self):
        """
        基本扫描，包括解析ip、url请求返回状态码、可能的robots.txt内容
        """
        if self.hostname_type == "domain":
            if self.resolved_ip_list:
                log.info(f"resolved_ip_list: {self.resolved_ip_list}")
            else:
                log.warning("unable to resolve to ip")
        basic_info = self.get_basic_info()
        url_status_code = basic_info.get("status_code", 0)
        if url_status_code:
            log.info(f"url status code: {url_status_code}")
            robots_info = basic_info.get("robots_info", "")
            if robots_info:
                robots_info_len = len(robots_info)
                if robots_info_len == 1:
                    log.info(f"site has robots.txt({len(robots_info)} byte):")
                else:
                    log.info(f"site has robots.txt({len(robots_info)} bytes):")
                if len(robots_info) < 80:
                    log.info(f"    content: {robots_info}")
                else:
                    log.info(f"    80 bytes content: {robots_info[:80]}")
                if Config.conf["save_flag"]:
                    robots_data_path = os.path.join(
                        Config.conf["analyze_data_path"], "robots.txt"
                    )
                    with open(robots_data_path, "wb") as f:
                        f.write(robots_info)
                    log.info("robots.txt saved")

    def link_and_subdomain_scan(self):
        """
        扫描url下所有链接和子域名
        如url为: http://www.example.com/hello/a.html
        则只获取 "/hello/" 路径下的url继续访问，符合直觉
        """
        if self.hostname_type == "domain":
            log.info("scanning link and subdomain...")
        else:
            log.info("scanning link...")
        if Config.conf["save_flag"]:
            links_file_path = os.path.join(
                Config.conf["analyze_data_path"], "url_links.txt"
            )
        ignore_tails = (
            ".jpg",
            ".png",
            ".gif",
            ".ico",
            ".svg",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            "pptx",
            ".apk",
            ".wav",
            ".zip",
            ".rar",
            ".7z",
        )

        path_limit = self.parsed_url.path
        if (
            path_limit.endswith((".html", ".php")) or path_limit.endswith(ignore_tails)
        ) and "/" in path_limit:
            path_limit = path_limit.rsplit("/", maxsplit=1)[0] + "/"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
            "Referer": "http://www.google.com",
        }

        self.links.append(self.main_url)
        links_to_req = [self.main_url]

        for link in links_to_req:
            log.info(f"request: {link}")
            try:
                res = requests.get(link, headers=headers)
            except Exception as e:
                log.error(f"{e.__class__} {link}")
                continue

            # 只处理文本形式的响应
            if "text/" not in res.headers.get("Content-Type", ""):
                continue

            half_links = re.findall(rb'(?:href|src|action)\s?=\s?"(.*?)"', res.content)
            half_links.extend(
                re.findall(rb"(?:href|src|action)\s?=\s?\'(.*?)\'", res.content)
            )
            if self.hostname_type == "domain":
                possible_subdomain_list = re.findall(
                    rb"https?://((?:[-a-zA-Z0-9]+\.){2,}[a-zA-Z]+)", res.content
                )
                for possible_subdomain in possible_subdomain_list:
                    possible_subdomain = possible_subdomain.decode()
                    if (
                        possible_subdomain.endswith(self.basic_domain)
                        and possible_subdomain not in self.subdomain_list
                    ):
                        self.subdomain_list.append(possible_subdomain)

            for half_link in half_links:
                half_link = half_link.decode()
                joined_link = urljoin(res.url, half_link)
                joined_link_rstrip = joined_link.rstrip("/")
                if (
                    not joined_link_rstrip.startswith("javascript:")
                    and joined_link_rstrip not in self.links
                ):
                    self.links.append(joined_link_rstrip)
                    if Config.conf["save_flag"]:
                        with open(links_file_path, "a") as f:
                            f.write(f"{joined_link_rstrip}\n")
                # 链接在本站下、在同一父path下、不是资源链接、不在待请求列表里，则添加到待请求列表
                parsed_joined_link_rstrip = urlparse(joined_link_rstrip)
                if (
                    self.hostname == parsed_joined_link_rstrip.hostname
                    and parsed_joined_link_rstrip.path.startswith(path_limit)
                    and not joined_link_rstrip.endswith(ignore_tails)
                    and joined_link_rstrip not in links_to_req
                ):
                    links_to_req.append(joined_link_rstrip)

        log.info(f"link num: {len(self.links)}")
        if self.hostname_type == "domain" and self.subdomain_list:
            log.info(f"subdomain_list: {self.subdomain_list}")

    def run(self):
        self.basic_scan()
        if self.deep_flag:
            self.link_and_subdomain_scan()
