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

    segments = address.split(".")
    reversed_ip = ".".join(reversed(segments))
    req = reversed_ip +"."+ checker
    try:
        results = socket.getaddrinfo(req,53)
        print(
"""
Return Code	Zone	Description
127.0.0.2	SBL	Spamhaus SBL Data
127.0.0.3	SBL	Spamhaus SBL CSS Data
127.0.0.4	XBL	CBL Data
127.0.0.9	SBL	Spamhaus DROP/EDROP Data (in addition to 127.0.0.2, since 01-Jun-2016)
127.0.0.10	PBL	ISP Maintained
127.0.0.11	PBL	Spamhaus Maintained
""")
        print(results)
        print(f"{domain} is SPAM")
    except:
        #応答がない=spamhausに登録されていなかった
        print(f"{domain} is not SPAM")

