import socket

checker = "zen.spamhaus.org"

#zenというサーバからipを入力し，Ａレコードがあったらスパム判定
def check_zenbl(domain):
    try:
        address = socket.gethostbyname(domain)
    except:
        #メールドメインをIPに出来なかった(見つからなかった)
        print(f"{domain} IP not found")
        return 0
    
    for a in address:
        ip = a
    segments = ip.split(".")
    reversed_ip = ".".join(reversed(segments))
    try:
        results = socket.getaddrinfo(reversed_ip +"."+ checker,80)
        for result in results:
            print(result)
    except:
        #spamhausに登録されていなかった
        print(f"{domain} is not SPAM")

#--------以下 abuseIPDBを使用---------------------
import requests
import json
#import socket

json_open = open('api.json', 'r')
json_load = json.load(json_open)
api = json_load["api"]

def abuse_check(domain):
    address = ""
    try:
        address = socket.gethostbyname(domain)
    except:
        #メールドメインをIPに出来なかった(見つからなかった)
        print(f"{domain} IP not found")
        return 0
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': f'{address}',
    }

    headers = {
        'Accept': 'application/json',
        'Key': api
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    
