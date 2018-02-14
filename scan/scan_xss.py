import re
# import requests
import urllib.request as urequest
import random
from bs4 import BeautifulSoup
import lxml
import string
import optparse
import sys
import Request
import time

headers = {'User-Agent':"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1"}


class scan_xss(object):
    def __init__(self,url='',data='',cookies=''):
        self.url = url if url else ''
        self.data = data if data else {}
        self.cookies = cookies
        # self.cookies = {}
        self.requests = Request.download()
        # self.lock = lock
        # if cookies:
        #     cookies = cookies.split(';')
        #     try:
        #         for i in range(len(cookies)):
        #             part = cookies[i].split('=')
        #             self.cookies[part[0]] = str(part[1])
        #     except Exception as e:
        #         print('split error')
        self.CHAR_POOL = ('\'', '"', '>', '<', ';')
        self.PREFIX_SUFFIX_LENGTH = 3
        self.DOM_PATTERNS = (
            r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
            r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
        )
        self.REGULAR_PATTERNS = (
            (r"<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering"),
            (r'<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering"),
            (r"<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering"),
            (r">[^<]*%(chars)s[^<]*<", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering"),
            (r"<[^>]*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering"),
            (r'<[^>]*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering"),
            (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering"),
                            )
        # 处理data
        D = ''
        try:
            if self.data:
                for i,j in self.data.items():
                    D += '%s%s%s%s' % (i, '=', j, '&')
                D = D.rstrip('&')
        except:
            pass
        finally:
            self.data = D

    def _receive_content(self,url='', data=None, method="GET"):  # 默认get request
        res=''
        try:
            if method is "GET":
                # res = self.requests.get(url,headers= headers,cookies=cookies).text
                res = self.requests.get(url, cookies=self.cookies).text
            else:
                if data: data = self._splitdata(data)
                # res = self.requests.post(url, headers=headers, data=data, cookies=cookies).text
                res = self.requests.post(url, data=data, cookies=self.cookies).text
        except Exception as e:
            print('xss_receivecontent_error:', str(e))
            res = ''
        finally:
            return res

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
    # _splitdata('formhash=9664f5d3&referer=http%3A%2F%2Fwww.xianzhenyuan.cn%2F.%2F&loginfield=username&username=')

    def _contains(self,content,chars):
        return all(char in content for char in chars)

    def scan_page(self):
        retval = False
        original = self._receive_content(self.url,self.data)
        # dom = (re.findall(_, original) for _ in self.DOM_PATTERNS)
        # if any(dom):
        #     print('[*]there may be dom xss:%s' % (dom))
            # retval = True

        for method in ("GET","POST"):
            GDurl = ('%s&%s' % (self.url, self.data) if self.url.find('?') > -1 else '%s?%s' % (self.url, self.data)) if self.data and method is "GET" else self.url
            current = self.data if self.data and method is "POST" else GDurl
            for match in re.finditer(r'((\A|[&?])(?P<parameter>[\w\[\]]+=)(?P<value>[^&#]*))',current):
                print('[*]%s scaning %s'%(method,match.group('parameter')))
                prefix, suffix = (''.join(random.sample(string.ascii_letters, self.PREFIX_SUFFIX_LENGTH)) for _ in range(2))
                # prepare = "%s%s%s"%(prefix,urequest.quote(''.join(random.sample(self.CHAR_POOL,len(self.CHAR_POOL)))),suffix)
                prepare = "%s%s%s" % (prefix,''.join(random.sample(self.CHAR_POOL, len(self.CHAR_POOL))), suffix)
                # print('test:',current,prepare,match.group(0))
                payload = current.replace(match.group(0),'%s%s'%(match.group(0),prepare))
                print('[*]',method,'payload:',payload)
                content = self._receive_content(payload) if method is "GET" else (self._receive_content(self.url,payload,"POST") if self.data else self._receive_content(payload,'',"POST") )
                # print(content)
                for scout in re.finditer('(?s)%s(.+?)%s'%(prefix,suffix),content,re.I):
                    # print('[*]scout:','%s'%scout)
                    for regex, must, info in self.REGULAR_PATTERNS:
                        context = re.findall(regex%{'chars':scout.group(0)},content,re.I)
                        if len(context) > 0:
                            # print('[*]%s'%context)
                            for i in range(len(context)):
                                if self._contains(context[i],must):
                                    retval = True
                                    print('%s there may be xss: %s'%(method,match.group('parameter')))
                                    # self.lock.acquire()
                                    with open('d:\\scan_results.txt', 'a') as fd:
                                        fd.write('%s there may be xss: %s | %s  %s' % (
                                        method, self.url, match.group('parameter'), time.ctime()) + '\n')
                                    # self.lock.release()
                                    return retval

        return retval




# sd = scan_xss('http://www.hbxffy.com/info/dispnews.asp?id=2073')
# sd.scan_page()




# if __name__=='__main__':
#     parse = optparse.OptionParser()
#     parse.add_option('-u', dest="url", help='Target URL(eg:http://127.0.0.1/dwva/vulnerabilities/sqli/?id=1)')
#     parse.add_option('-c', '--cookie', dest='cookies', help='HTTP Cookie header')
#     parse.add_option('-d', dest='data', help='POST Data')
#     parse.add_option('-p', dest='proxies', help='HTTP Proxy')
#     cookies = {}
#     option, args = parse.parse_args(sys.argv[1:])
#     d = option.cookies
#     if d:
#         d = d.replace(' ','')
#         s_cookies = d.split(';')
#         try:
#             for i in range(len(s_cookies)):
#                 part = s_cookies[i].split('=')
#                 cookies[part[0]] = str(part[1])
#         except Exception as e:
#             print('cookies error')
#     url = option.url if option.url else ''
#     data = option.data if option.data else ""
#     proxy = option.proxies if option.proxies else ''
#     proxies = {'HTTP': proxy}
#     S = scan_xss(url,data,cookies)
#     print(S.scan_page())
