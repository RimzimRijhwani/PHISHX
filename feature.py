import re
import socket
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

class FeatureExtraction:
    def __init__(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        self.url = url
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc

        try:
            self.page_html = requests.get(self.url, timeout=5).text
            self.soup = BeautifulSoup(self.page_html, "html.parser")
        except:
            self.page_html = ""
            self.soup = None

    def getFeaturesList(self):
        return [
            self.using_ip(),
            self.long_url(),
            self.short_url(),
            self.symbol_at(),
            self.prefix_suffix(),
            self.sub_domains(),
            self.https_check(),
            self.domain_reg_len(),
            self.request_url(),
            self.info_email(),
            self.abnormal_url(),
            self.iframe_redirection(),
            self.age_of_domain(),
            self.dns_recording(),
            self.google_index()
        ]

    def using_ip(self):
        try:
            socket.inet_aton(self.domain)
            return -1
        except:
            return 1

    def long_url(self):
        return -1 if len(self.url) >= 75 else (0 if len(self.url) >= 54 else 1)

    def short_url(self):
        return 1 if len(self.url) < 30 else -1

    def symbol_at(self):
        return -1 if '@' in self.url else 1

    def prefix_suffix(self):
        return -1 if '-' in self.domain else 1

    def sub_domains(self):
        dots = self.parsed.hostname.count('.') if self.parsed.hostname else 0
        return -1 if dots > 3 else (0 if dots == 3 else 1)

    def https_check(self):
        return 1 if self.parsed.scheme == 'https' else -1

    def domain_reg_len(self):
        try:
            w = whois.whois(self.domain)
            creation = w.creation_date
            expiration = w.expiration_date
            if isinstance(creation, list): creation = creation[0]
            if isinstance(expiration, list): expiration = expiration[0]
            return -1 if (expiration - creation).days <= 365 else 1
        except:
            return -1

    def request_url(self):
        return 1 if self.domain in self.url else -1

    def info_email(self):
        return -1 if "mailto:info@" in self.page_html or "info@" in self.page_html else 1

    def abnormal_url(self):
        try:
            host = socket.gethostbyname(self.domain)
            return 1 if host else -1
        except:
            return -1

    def iframe_redirection(self):
        if self.soup:
            return -1 if self.soup.find_all("iframe") else 1
        return 1

    def age_of_domain(self):
        try:
            w = whois.whois(self.domain)
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            age_days = (datetime.now() - creation).days
            return -1 if age_days < 180 else 1
        except:
            return -1

    def dns_recording(self):
        try:
            socket.gethostbyname(self.domain)
            return 1
        except:
            return -1

    def google_index(self):
        try:
            from googlesearch import search
            result = list(search(self.url, num=1, stop=1))
            return 1 if result else -1
        except:
            return -1
