from flask import request
from core.tester import *


class Data(Tester):

    def get_testers(self):
        self.testers = request.form.getlist('checkbox')

    def get_addressess(self):
        self.addresses = request.form['urls'].replace(" ", "").splitlines()

    def run(self):
        self.data[0].append('Address')
        self.data[0].extend(self.addresses)

        if 'virustotal' in self.testers:
            pool = ThreadPool(8)
            pool.map(self.pre_virustotal, self.addresses)

        if 'bluecoat' in self.testers:
            pool = ThreadPool(8)
            self.bluecoat_result.extend(pool.map(self.bluecoat, self.addresses))
            self.data.append(self.bluecoat_result)

        if 'xforce' in self.testers:
            pool = ThreadPool(8)
            self.xforce_result.extend(pool.map(self.xforce, self.addresses))
            self.data.append(self.xforce_result)

        if 'mcafee' in self.testers:
            pool = ThreadPool(8)
            self.mcafee_result.extend(pool.map(self.mcafee, self.addresses))
            self.data.append(self.mcafee_result)

        if 'ciscoblacklist' in self.testers:
            pool = ThreadPool(8)
            self.ciscoblacklist_result.extend(pool.map(self.cisco_blacklist, self.addresses))
            self.data.append(self.ciscoblacklist_result)

        if 'talos' in self.testers:
            pool = ThreadPool(8)
            self.talos_result.extend(pool.map(self.talos, self.addresses))
            self.data.append(self.talos_result)

        if 'ipvoid' in self.testers:
            pool = ThreadPool(8)
            self.ipvoid_result.extend(pool.map(self.ipvoid, self.addresses))
            self.data.append(self.ipvoid_result)

        if 'virustotal' in self.testers:
            pool = ThreadPool(8)
            self.virustotal_result.extend(pool.map(self.virustotal, self.addresses))
            self.data.append(self.virustotal_result)

    # def print_data(self):
    #     data = []
    #     data.extend([self.xforce_result, self.mcafee_result])
    #     return data

    def show_data(self):
        result = []
        for i in range(0, len(self.data[0])):
            temp = []
            for items in self.data:
                temp.append(items[i])
            result.append(temp)
        return result

