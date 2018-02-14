import requests
import re
import random
import time

class download:
    def __init__(self):
        self.iplist = ['124.207.126.15:808',
                       '115.231.105.109:8081',
                       '115.231.175.68:8081',
                       '125.217.199.148:8197',
                       '59.44.247.126:9797',
                       '113.200.245.158:9999',
                       '202.197.127.139:1209',
                       '220.249.185.178:9999',
                       '221.237.154.58:9797',
                       '119.57.105.237:8080',
                       '59.44.16.8:80',
                       '171.36.165.208:9797',
                       '210.44.213.63:1080',
                       '1.82.132.85:8080',
                       '1.82.216.135:80',
                       '61.134.29.88:8080',
                       '123.139.56.238:9999',
                       '61.134.29.88:8080',
                       '124.89.33.75:9999',
                       '113.143.69.192:808',
                       '1.82.33.191:8998',
                       '113.140.25.4:81',
                       '123.138.89.130:9999',
                       ]
        self.user_agent_list = [
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1",
            "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
            "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24"
        ]

    def get(self,url,timeout=2,proxy=None,retries=1,cookies=None):
        UA = random.choice(self.user_agent_list)
        headers = {'User-Agent': UA}
        if proxy == None:
            try:
                return requests.get(url, headers=headers, timeout=timeout,cookies=cookies)
            except:
                if retries > 0:
                    return self.get(url,retries=retries-1)
                else:
                    print(u'开始使用代理')
                    IP = ''.join(str(random.choice(self.iplist)).strip())
                    proxy = {'http': IP}
                    return self.get(url ,proxy=True,retries=1)
                    # return False
        else:
            try:
                IP = ''.join(str(random.choice(self.iplist)).strip())
                proxy = {'http': IP}
                print(u'当前代理是',IP)
                return requests.get(url, headers=headers, proxies=proxy, timeout=timeout,cookies=cookies)
            except:
                print(u'代理%s失敗'%IP)
                if retries > 0:
                    IP = ''.join(str(random.choice(self.iplist)).strip())
                    proxy = {'http': IP}
                    print(u'更换代理')
                    return self.get(url,proxy=True, retries = retries - 1)
                else:
                    print('Request Failed %s'%url)
                    return None

    def post(self,url,data=None,timeout=2,proxy=None,retries=1,cookies=None):
        UA = random.choice(self.user_agent_list)
        headers = {'User-Agent': UA}
        if proxy == None:
            try:
                return requests.post(url,data=data ,headers=headers, timeout=timeout,cookies=cookies)
            except:
                if retries > 0:
                    return self.post(url,retries= retries-1)
                else:
                    print(u'开始使用代理')
                    IP = ''.join(str(random.choice(self.iplist)).strip())
                    proxy = {'http': IP}
                    return self.post(url,proxy=True)

        else:
            try:
                IP = ''.join(str(random.choice(self.iplist)).strip())
                proxy = {'http': IP}
                print(u'当前代理是',IP)
                return requests.post(url, headers=headers,data=data ,proxies=proxy, timeout=timeout,cookies=cookies)
            except:
                print(u'代理%s失敗'%IP)
                if retries > 0:
                    IP = ''.join(str(random.choice(self.iplist)).strip())
                    proxy = {'http': IP}
                    print(u'更换代理')
                    return self.post(url,proxy=True,retries=retries - 1)
                else:
                    print('Request Failed %s'%url)
                    return None

