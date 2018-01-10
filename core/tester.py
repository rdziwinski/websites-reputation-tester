from multiprocessing.dummy import Pool as ThreadPool
from random import randint
from urllib.parse import urlparse

import json
import re
import requests
import socket
import time
import validators
import webbrowser
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth


class Tester:
    def __init__(self, address):
        self.address = address

    # RETURN 110 IF URL, 111 IF IP, 112 IF WRONG ADDRESS
    def url_or_ip(url):
        if validators.domain(url) is True or validators.url(url) is True:
            return 110  # URL
        elif validators.ipv4(url) is True:
            return 111  # IP
        else:
            return 112  # Error
