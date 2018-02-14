#coding=utf-8
# import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import queue
import threading
import Request
import scan_xss,scan_sqlinject
import searchinput
import traceback
import time

class ScraperWorkBase(object):
    def __init__(self,url,filter_domain,cookies,lock):
        self.target_url = url if url else ''
        self.base_domain = filter_domain if filter_domain else urlparse(url)[1]
        self.response = None
        self.soup = None
        self.requests  = Request.download()
        self.lock = lock
        self.cookies = {}
        if cookies:
            cookies = cookies.replace(' ','')
            cookies = cookies.split(';')
            try:
                for i in range(len(cookies)):
                    part = cookies[i].split('=')
                    self.cookies[part[0]] = str(part[1])
            except Exception as e:
                print('split error')
        # print(self.cookies)

    def dule_relative_path(self,url):
        base = urlparse(self.target_url)
        x = urlparse(url)
        if x[0] == '' and x[1] == '':
            print('Fix URL:'+url+' in ',self.target_url)
            if '../' not in url:
                # url = base[0] + '://' + base[1] + '/test'+'/' + url
                url = base[0] + '://' + base[1] +'/' + url
                url = url[:8] + url[8:].replace('//', '/')
                print('[*]', url)
            else:
                # url = base[0] + '://' + base[1] + base[2] + '/' + url
                url = base[0] + '://' + base[1] + re.sub(r'[^/]+\..+','',base[2]) + '/' + url
                url = url[:8] + url[8:].replace('//', '/')
                # print(url)
                xx = urlparse(url)
                # print('[@]',xx[2])
                if '../' in xx[2]:
                    count = 1
                    path_s = xx[2].split('/')
                    # 从左往右遇到 ../ 进行处理
                    for i in range(len(path_s)):
                        if path_s[i] == '..':
                            path_s[i] = ''
                            if path_s[i - count]:
                                path_s[i - count] = ''
                                count += 2
                    # 构造新的path
                    tmp_path = '/'
                    for _ in range(len(path_s)):
                        if path_s[_] == '':
                            continue
                        tmp_path = tmp_path + path_s[_] + '/'
                    tmp_path = tmp_path.rstrip('/')
                    url = url.replace(xx[2], tmp_path)
            print('fixed url :', url)
        return url

    def check_url(self,url):
        x = urlparse(url)
        if 'http' not in x[0]:
            print('Bad Request  ' + url)
            self.lock.acquire()
            with open('d:\\badrequest.txt', 'a') as fd:
                fd.write('%s  %s'%(url,time.ctime()) + '\n')
            self.lock.release()
            return False
        elif self.base_domain not in x[1]:
            print('Different Domain ' + url)
            self.lock.acquire()
            with open('d:\\otherdomain.txt','a') as fd:
                fd.write('%s  %s'%(url,time.ctime())+'\n')
            self.lock.release()
            return False
        return url

    def filter_url(self,url):#过滤掉下载文件的链接（待完善），并将过滤掉的url记录到本地文件
        if re.findall(r'\.apk|doc|\.rar|\.zip|\.pdf|\.jpg|\.png|file|url|upload|forward|redirect|logout|create_db|exec|security|edit',url,re.I):
            print('filter url :' + url)
            xx = urlparse(url)
            if xx[0]:
                self.lock.acquire()
                with open('d:\\specialurl.txt', 'a') as fd:
                    fd.write('%s  %s'%(url,time.ctime()) + '\n')
                self.lock.release()
            else:
                url  = self.dule_relative_path(url)
                self.lock.acquire()
                with open('d:\\specialurl.txt', 'a') as fd:
                    fd.write('%s  %s'%(url,time.ctime()) + '\n')
                self.lock.release()
            return False
        return url


    def scan(self):
        pass
        # try:
        #     if self.target_url.find('?') > -1:
        #         sx = scan_xss.scan_xss(self.target_url,'',self.cookies)
        #         ss = scan_sqlinject.scan_sqlinj(self.target_url,'',self.cookies)
        #         print('scaning %s' % self.target_url)
        #         sx.scan_page()
        #         ss._scan_page()
        #     data = None
        #     if len(self.response.text):
        #         data = searchinput.get_input(self.response.text)
        #     if data:
        #         sx = scan_xss.scan_xss(self.target_url,data,self.cookies)
        #         ss = scan_sqlinject.scan_sqlinj(self.target_url,data,self.cookies)
        #         print('data scaning %s' % self.target_url)
        #         sx.scan_page()
        #         ss._scan_page()
        # except Exception as e:
        #     print('[//]',e)
        #     print(traceback.print_exc())

    def get_html_data(self):
        try:
            if self.check_url(self.target_url):
                self.response = self.requests.get(self.target_url, timeout=5,cookies=self.cookies)
                if self.response.history:
                    print('found redirect 3**')
                    self.lock.acquire()
                    with open('d:\\302.txt', 'a') as fd:
                        fd.write( '%s  %s'%(self.target_url,time.ctime()) + '\n')
                    print('success write in txt')
                    self.lock.release()
                title = re.search(r'<title>(.*)</title>',self.response.text)  # get the title
                if title:
                    title = title.group(1).strip().strip("\r").strip("\n")[:30]
                else:
                    title = "None"
                banner = ''
                try:
                    banner += self.response.headers['Server'][:50]  # get the server banner
                    print('[server]',banner)
                except:
                    pass
        except:
            print('request failed:'+self.target_url)
            self.lock.acquire()
            with open('d:\\failedrequest.txt', 'a') as fd:
                fd.write('%s  %s'%(self.target_url,time.ctime()) + '\n')
            self.lock.release()
            return ''
        print('GOT response')

        return self.response.text

    def get_soup(self):
        text = self.get_html_data()
        if not len(text):
            return []
        return BeautifulSoup(text,'lxml')

    def get_all_url(self):
        self.url_list = []

        self.soup = self.get_soup()
        if self.soup:
            all_a_link = self.soup.find_all('a', attrs={'href': re.compile('^[^#].+')})
        else:
            return None

        for i in all_a_link:
            url = i['href']
            if self.filter_url(url):
                url = self.dule_relative_path(url)
                if self.check_url(url):
                    self.url_list.append(url)
        return set(self.url_list)


# x = ScraperWorkBase('http://www.chd.edu.cn')
# print(len(x.get_all_url()))

class control(object):
    def __init__(self,thread_num=5,worker_class=ScraperWorkBase,base_domain='',cookies=''):
        self.thread_num = thread_num
        self.visited = set()
        self.dead = False
        self.count = 0
        self.worker_class = worker_class
        self.task_queue = queue.Queue()
        self.result = []
        self.all_url = []
        self.judge = []
        self.base_domain = base_domain
        self.cookies = cookies
        self.lock = threading.Lock()
        # self.table = Sql.MySql()
        # self.table.create_table('url')

    def scan_judge(self,url):
        xx = urlparse(url)
        result = []
        if xx[4]:
            c = xx[4].split('&')
            try:
                for i in range(len(c)):
                    part = c[i].split('=')
                    result.append(part[0])
                result.append(xx[1])
                result.append(xx[2])
            except Exception as e:
                print('url split error')
                return True
            if result in self.judge:
                # print(result)
                return False
            self.judge.append(result)
        else:
            if url in self.visited:
                return False
        return True

    def start_workers(self):
        pool = []
        for i in range(int(self.thread_num)):
            try:
                t = threading.Thread(target=self.worker)
                t.start()
                # pool.append(t)
            except:
                print('threading start error')
        for i in pool:
            i.join()
        # for url in self.result:
        #     self.table.insert('url',url,'no')



    def worker(self):
        while not self.dead:
            try:
                url = self.task_queue.get(block=True, timeout=6)
                if url in self.visited:
                    continue
                print('start work,url', url)
                self.count+=1
                print('work number is',self.count)

                if self.scan_judge(url):
                    self.visited.add(url)
                    self.result.append(url)
                    scraper = self.worker_class(url,self.base_domain,self.cookies,self.lock)
                    tmp_result = scraper.get_all_url()
                    if tmp_result is None:
                        pass
                    else:
                        for i in tmp_result:
                            if i in self.visited:
                                continue
                            if i not in self.all_url:
                                self.all_url.append(i)
                                self.task_queue.put(i)
                                self.result.append(i)
                            # self.task_queue.put(i)
                            # self.result.append(i)
                        scraper.scan()

            except queue.Empty:
                print('COMPLETE')
                self.kill()


    def fill_task(self,target_urls):
        if isinstance(target_urls,list):
            for i in target_urls:
                self.task_queue.put(i)
        else:
            print('target_urls must be list')

    def get_result(self):
        return self.result

    def kill(self):
        if not self.dead:
            self.dead = True


x = control(thread_num=5,base_domain='',cookies = '')
x.fill_task(['http://www.e-chinalife.com/'])
x.start_workers()

