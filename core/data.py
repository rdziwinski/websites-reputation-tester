from flask import request
from core.tester import *


class Data(Tester):
    def run(self):
        self.data[0].append('Address')
        self.data[0].extend(self.addresses)

        if 'xforce' in self.testers:
            pool = ThreadPool(8)
            self.xforce_result.extend(pool.map(self.xforce, self.addresses))
            self.data.append(self.xforce_result)

        if 'mcafee' in self.testers:
            pool = ThreadPool(8)
            self.mcafee_result.extend(pool.map(self.mcafee, self.addresses))
            self.data.append(self.mcafee_result)

        if 'virustotal' in self.testers:
            pool = ThreadPool(8)
            self.virustotal_result.extend(pool.map(self.virustotal, self.addresses))
            self.data.append(self.virustotal_result)

        if 'bluecoat' in self.testers:
            pool = ThreadPool(8)
            self.bluecoat_result.extend(pool.map(self.bluecoat, self.addresses))
            self.data.append(self.bluecoat_result)

        if 'ciscoblacklist' in self.testers:
            pool = ThreadPool(8)
            self.ciscoblacklist_result.extend(pool.map(self.cisco_blacklist, self.addresses))
            self.data.append(self.ciscoblacklist_result)

        if 'talos' in self.testers:
            pool = ThreadPool(8)
            self.talos_result.extend(pool.map(self.talos, self.addresses))
            self.data.append(self.talos_result)

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
