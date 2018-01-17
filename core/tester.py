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
from flask import request


class Tester:
    def __init__(self):
        self.xforce_result = ['X-Force']
        self.mcafee_result = ['McAfee']
        self.virustotal_result = ["VirusTotal"]
        self.bluecoat_result = ['BlueCoat']
        self.ciscoblacklist_result = ['Cisco Blacklist']
        self.talos_result = ['Talos']
        self.ipvoid_result = ['IpVoid']
        self.data = [[]]

    def init_status(self):
        # Generaly
        self.s110 = "Enter IP address, URL is not supported."
        self.s111 = "Enter URL, IP is not supported."
        self.s120 = "Enter correct IP address"
        self.s121 = "Enter correct URL"
        self.s112 = "Enter correct URL or IP"
        self.s113 = "There was an error, please contact:  rdziwinski@gmail.com"

        # Cisco Black List
        self.s0 = "No"
        self.s1 = "Yes"

        # BlueCoat
        self.s131 = "You have enter Captcha"

        # NsLookup
        self.s141 = "URL not found for this IP address"
        self.s142 = "IP not found for this URL"

        # McAfee
        self.s151 = "Minimal Risk"
        self.s152 = "Unverified"
        self.s153 = "Medium Risk"
        self.s154 = "High Risk"
        self.s155 = "No data"

        # XForce
        self.s161 = "Authorization fault"
        self.s162 = "Unknown"
        self.s163 = "Overloaded, try again in a moment."

        # Zulu
        self.s171 = "Analysis lasted too long"

    # RETURN 110 IF URL, 111 IF IP, 112 IF WRONG ADDRESS
    def url_or_ip(self, url):
        if validators.domain(url) is True or validators.url(url) is True:
            return 110  # URL
        elif validators.ipv4(url) is True:
            return 111  # IP
        else:
            return 112  # Error

    # RETURN S112 IF WRONG ADDRESS, 0 IF NOT REANALYSE, 1 IF REANALYSE
    def pre_virustotal(self, url):
        if self.url_or_ip(url) == 112:
            return self.s112
        else:
            post_request = {'url': url}
            headers = {'Referer': 'https://www.virustotal.com/'}
            result = requests.post("https://www.virustotal.com/en/url/submission/", data=post_request, headers=headers)
            data = json.loads(result.text)
            if 'reanalyse_url' not in result.text:
                return 0
            reanalyse = str(data['reanalyse_url'])
            reanalyse_url = "https://www.virustotal.com" + reanalyse
            requests.get(reanalyse_url)
            return 1

    # RETURN 112 IF WRONG ADDRESS, STRING CATEGORY IF OK, S131 IF CAPTCHA, 132 IF BAD URL BY BLUECOAT
    def bluecoat(self, url):
        if self.url_or_ip(url) == 112:
            return self.s112

        post_request = {'url': url}
        result = requests.post("http://sitereview.bluecoat.com/rest/categorization",
                               headers={"User-Agent": "Mozilla/5.0"},
                               data=post_request)
        if 'Please complete the CAPTCHA' in result.text:
            return self.s131
        if 'badurl' in result.text:
            return self.s121
        data = json.loads(result.text)
        category = str(data['categorization'])
        soup = BeautifulSoup(category, 'html.parser')
        return soup.get_text()

    def bluecoat_sleep(self, raport):
        results = []
        j = 0
        for url, i in zip(raport, range(len(raport))):
            results.append(self.bluecoat(url))
            j += 1
            if j % 10 == 0:
                time.sleep(30)
                # results.append("czekamy")
        return results

    # RETURN XFORCEURL IF URL, XFORCEIP IF IP, S112 IF WRONG URL
    def xforce(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 110:
            return self.xforce_url(url)
        elif urlorip == 111:
            return self.xforce_ip(url)
        elif urlorip == 112:
            return self.s112

    # RETURN S114 IF NOT AUTHORIZED, STRING IF OK, S113 IF ERROR
    def xforce_ip(self, url):
        risk_request = 'https://api.xforce.ibmcloud.com/ipr/' + url
        malware_request = 'https://api.xforce.ibmcloud.com/ipr/malware/' + url

        auth = HTTPBasicAuth('06d8ddbb-9c04-4a1d-9bdf-72470714373a', '43a43e47-d205-46a5-bfb4-9de9f609c0de')

        risk_result = requests.get(risk_request, auth=auth)
        malware_result = requests.get(malware_request, auth=auth)

        risk = json.loads(risk_result.text)
        malware = json.loads(malware_result.text)

        if 'Not authorized.' in risk_result.text:
            return self.s161
        elif str(malware['malware']) == '[]':
            risk_number = str(risk['score'])
            return "Risk: " + risk_number
        elif 'firstseen' in malware_result.text:
            risk_number = str(risk['score'])
            malware_number = len(malware['malware'])
            i = 0
            malware_family = []
            while i < len(malware['malware']):
                malware_family.append(''.join(malware['malware'][i]['family']))
                i += 1
            return "Risk: " + risk_number + ", Malware: " + str(malware_number) + " " + ", ".join(set(malware_family))
        else:
            return self.s113

    # RETURN S114 IF NOT AUTHORIZED, STRING IF OK, S113 IF ERROR
    def xforce_url(self, url):
        risk_request = 'https://api.xforce.ibmcloud.com/url/' + url
        malware_request = 'https://api.xforce.ibmcloud.com/url/malware/' + url

        auth = HTTPBasicAuth('06d8ddbb-9c04-4a1d-9bdf-72470714373a', '43a43e47-d205-46a5-bfb4-9de9f609c0de')

        risk_result = requests.get(risk_request, auth=auth)
        malware_result = requests.get(malware_request, auth=auth)
        try:
            risk = json.loads(risk_result.text)
            malware = json.loads(malware_result.text)
        except:
            return self.s163

        # return malware['malware'][178]['family'][0]

        if 'Not authorized.' in risk_result.text:
            return self.s161
        elif 'Not found.' in risk_result.text and 'Not found.' in malware_result.text:
            return self.s162
        elif 'Not found.' in malware_result.text:
            risk_number = str(risk['result']['score'])
            return "Risk: " + risk_number
        elif 'Not found.' in risk_result.text and 'count' in malware_result.text:
            malware_number = str(malware['count'])
            i = 0
            malware_family = []
            while i < len(malware['malware']):
                malware_family.append(''.join(malware['malware'][i]['family'][0]))
                i += 1
            return "Risk: Unknown" + ", Malware: " + malware_number + " " + ", ".join(set(malware_family))
        else:
            risk_number = str(risk['result']['score'])
            malware_number = str(malware['count'])
            i = 0
            malware_family = []
            while i < len(malware['malware']):
                malware_family.append(''.join(malware['malware'][i]['family'][0]))
                i += 1
            return "Risk: " + risk_number + ", Malware: " + malware_number + " " + ", ".join(set(malware_family))

    # RETURN McAfeeURL IF URL, McAfeeIP IF IP, S112 IF WRONG URL
    def mcafee(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 110:
            return self.mcafee_url(url)
        elif urlorip == 111:
            return self.mcafee_ip(url)
        elif urlorip == 112:
            return self.s112

    # RETURN STRING RISK IF RISK DETECTED, S151 IF NO DATA, S113 IF ERROR
    def mcafee_ip(self, url):
        post_request = {'url': url}
        result = requests.post(
            'https://www.mcafee.com/threat-intelligence/ip/default.aspx?ip=' + url,
            data=post_request)
        soup = BeautifulSoup(result.text, 'html.parser')
        risk_results = [1, 2, 3]
        risk = []
        time.sleep(1)
        try:
            risk_results[0] = soup.find(id="ctl00_breadcrumbContent_imgRisk").get('src')
            risk_results[1] = soup.find(id="ctl00_breadcrumbContent_imgRisk1").get('src')
            risk_results[2] = soup.find(id="ctl00_breadcrumbContent_imgRisk2").get('src')
        except:
            return 155
        for reputaton in risk_results:
            if reputaton == '/img/Threat_IP/rep_minimal.png':
                risk.append(151)
            elif reputaton == '/img/Threat_IP/rep_unverified.png':
                risk.append(152)
            elif reputaton == '/img/Threat_IP/rep_medium.png':
                risk.append(153)
            elif reputaton == '/img/Threat_IP/rep_high.png':
                risk.append(154)
            else:
                return self.s155
                # return soup

        return "Web: " + risk[0] + ", Email: " + risk[1] + ", Network: " + risk[2]

    # RETURN STRING RISK IF RISK DETECTED, S151 IF NO DATA, S152 IF UNVERIFIED, S113 IF ERROR
    def mcafee_url(self, url):
        post_request = {'url': url}
        result = requests.post(
            'http://www.mcafee.com/threat-intelligence/site/default.aspx?region=us&threatRadio=Website&threatGo=Go&url=' + url,
            data=post_request)
        soup = BeautifulSoup(result.text, 'html.parser')

        try:
            risk = soup.find(id="ctl00_breadcrumbContent_imgRisk").get('alt')
        except AttributeError:
            return self.s155
        if risk == 'Minimal' or risk == 'Medium' or risk == 'High':
            return risk + ' Risk'
        elif risk == 'Unverified':
            return self.s152
        else:
            return self.s113

    # RETURN S112 IF WRONG URL, STRING RATING IF OK
    def virustotal(self, url):  # READY
        if self.url_or_ip(url) == 112:
            return self.s112
        else:
            post_request = {'url': url}
            headers = {'Referer': 'https://www.virustotal.com/'}
            result = requests.post("https://www.virustotal.com/en/url/submission/", data=post_request, headers=headers)
            if 'Invalid URL' in result.text:
                return self.virustotal(url)
            rating_results = json.loads(result.text)
            positives = str(rating_results['positives'])
            total = str(rating_results['total'])
            # date = str(ratingResults['last_analysis_date'])
            rating = positives + "/" + total
            return rating

    # RETURN S111 IF IP IN ARGUMENT, S112 IF WRONG URL, STRING IP IF OK, S113 IF ERROR
    def nslookup(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 111:
            try:
                ip = socket.gethostbyaddr(url)
                return str(ip[0])
            except:
                return self.s141
        elif urlorip == 112:
            return self.s121
        elif urlorip == 110:
            try:
                ip = socket.getaddrinfo(url, 80)
                return str(ip[0][4][0])
            except:
                return self.s142
        else:
            return self.s113

    # RETURN S1 IF YES, S2 IF NOT, S113 IF ERROR
    def check_cisco_blacklist(self, url):
        cisco_blacklist = requests.get('http://www.talosintelligence.com/feeds/ip-filter.blf')
        if url in cisco_blacklist.text:
            return self.s1
        elif url not in cisco_blacklist.text:
            return self.s0
        else:
            return self.s113

    # RETURN checkCiscoBlacklist IF URL OR IP IN ARGUMENT, S113 IF ERROR
    def cisco_blacklist(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 111:
            return self.check_cisco_blacklist(url)
        elif urlorip == 110:
            ip = self.nslookup(url)
            if ip == 142:
                return self.s142
            else:
                return self.check_cisco_blacklist(ip)
        else:
            return self.s112

    # RETURN STRING RATING IF OK, S113 IF ERROR
    def check_ipvoid(self, url):
        post_request = {'ip': url}
        result = requests.post(
            'http://www.ipvoid.com/ip-blacklist-check/',
            data=post_request)
        soup = BeautifulSoup(result.text, 'html.parser')

        success = soup.find("span", {"class": "label-success"})
        warning = soup.find("span", {"class": "label-warning"})
        danger = soup.find("span", {"class": "label-danger"})

        if success is None:
            if warning is None:
                try:
                    blacklisted_result = danger.text
                    blacklisted = blacklisted_result.replace("BLACKLISTED", "")
                    return blacklisted
                except:
                    return self.s113
            else:
                try:
                    blacklisted_result = warning.text
                    blacklisted = blacklisted_result.replace("BLACKLISTED ", "")
                    return blacklisted
                except:
                    return self.s113
        else:
            try:
                blacklisted_result = success.text
                blacklisted = blacklisted_result.replace("POSSIBLY SAFE ", "")
                return blacklisted
            except:
                return self.s113

    # RETURN checkIpVoid IF OK, S112 IF WRONG URL
    def ipvoid(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 111:
            return self.check_ipvoid(url)
        elif urlorip == 110:
            ip = self.nslookup(url)
            return self.check_ipvoid(ip)
        else:
            return self.s112

    def zulu(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 112:
            return self.s112
        try:
            seconds = randint(0, 3)
            time.sleep(seconds)
            post_request = {'submission[submission]': url,
                            'submission[user_agent]': 'ie7'}
            result = requests.post("http://zulu.zscaler.com/create", data=post_request).text
            number = re.search('\/status\/[a-zA-Z0-9-]+', result).group().replace("/status/", "")
            url_to_open = "http://zulu.zscaler.com/submission/show/" + number
            webbrowser.open(url_to_open)
        except:
            return self.s113

    def check_talos_ip(self, url):
        try:
            referer = 'https://www.talosintelligence.com/reputation_center/lookup?search='+url
            details = "https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fip%2F&query_entry="+url+"&offset=0&order=ip+asc"
            headers = {'Referer': referer}
            request = requests.get(details, headers=headers).text
            result = json.loads(request)
            email_reputation = str(result['email_score_name'])
            web_reputation = str(result['web_score_name'])
            reputation = "Email reputation: " + email_reputation + ", Web reputation: " + web_reputation
            return reputation
        except:
            return self.s113

    def check_talos_url(self, url):
        try:
            referer = 'https://www.talosintelligence.com/reputation_center/lookup?search='+url
            details = "https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry="+url+"&offset=0&order=ip+asc"
            headers = {'Referer': referer}
            request = requests.get(details, headers=headers).text
            result = json.loads(request)
            if 'error' in str(result) and str(
                    result['error']) == 'Unfortunately, we can\'t find any results for your search.':
                return self.s155
            elif str(result['category']) == 'None':
                web_reputation = str(result['web_score_name'])
                reputation = "Web reputation: " + web_reputation
                return reputation
            else:
                web_reputation = str(result['web_score_name'])
                category = str(result['category']['description'])
                reputation = "Web reputation: " + web_reputation + ", Category: " + category
                return reputation
        except:
            return self.s113

    def talos(self, url):
        urlorip = self.url_or_ip(url)
        if urlorip == 111:
            return self.check_talos_ip(url)
        elif urlorip == 110:
            return self.check_talos_url(url)
        elif urlorip == 112:
            return self.s112
