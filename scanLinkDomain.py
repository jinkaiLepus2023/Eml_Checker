import requests
import json
import time
import os
from html.parser import HTMLParser

#分析結果のHTMLから必要な情報(現段階ではURLの判定結果，スクリーンショット，サイト内リンクの3つ)を抽出
class ResultParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._in_primaryDomain = True    #解析されたドメインの表示ブロック内にいるかどうか
        self._in_h4 = False              #h4ブロック内にいるかどうか
        self._in_verdict = False         #解析結果の存在するブロック内にいるかどうか
        self._in_links = False           #サイト内リンク一覧の存在するブロック内にいるかどうか
        self._in_linkTxt = False         #サイト内リンクのドメインが表示されるブロック内にいるかどうか
        self._screenshotURL = ""         #スクリーンショットURLの格納場所
        self._verdictResult = ""         #解析結果の格納場所
        self._inSiteLinkDomains = set([])#サイト内リンクの格納場所
        self._effectiveDomain = ""       #実際に解析されたドメインの格納場所

    def handle_starttag(self, tag, attrs):
        if tag == "img" and len(attrs) > 0:    #スクリーンショットの存在するURLを取得する
            if attrs[0][1] == "screenshot":
                self._screenshotURL = attrs[1][1]
        if tag == "div" and len(attrs) > 2:
            if attrs[2][1] == "links":
                self._in_links = True
            if attrs[2][1] == "redirects":
                self._in_links = False
        if tag == "h4":
            self._in_h4 = True
        if tag == "span" and len(attrs) > 0:
            if attrs[0][1] == "primaryHostname":
                self._in_primaryDomain = True
            if attrs[0][1] == "text-success bold":
                self._in_linkTxt = True

    def handle_endtag(self, tag):
        if self._in_h4 == True and tag == "h4":
            self._in_h4 = False
            self._in_verdict = False

    def handle_data(self, data):
        if self._in_primaryDomain == True:  #実際に解析されたドメインの取得
            self._effectiveDomain = data
            self._in_primaryDomain = False
        if self._in_verdict == True:        #解析結果の取得
            self._verdictResult += data
        if self._in_h4 == True:             #解析結果の取得
            if data == "urlscan.":
                self._in_verdict = True
                self._verdictResult += data
        if self._in_linkTxt == True:        #サイト内リンクの取得
            self._inSiteLinkDomains.add(data)
            self._in_linkTxt = False


#URLをurlscan.ioに投げて解析を依頼する
def scanRequest(domain):
    #urlscan.io API要求を作成してpost，リンクのドメイン部分を解析してもらう
    headers = {'API-Key':'ここにAPIキーを記述','Content-Type':'application/json'}
    data = {"url": domain, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan',headers=headers, data=json.dumps(data))
    return response

#解析結果をurlscan.ioのリンクから取得する
def accessResult(resultURL, domain):
    resultHtml = requests.get(resultURL)
    resultParser = ResultParser()
    resultParser.feed(resultHtml.text)
    #スクリーンショットはresultpngディレクトリ内に「URL.png」というファイル名で保存
    screenshotURL = "https://urlscan.io" + resultParser._screenshotURL
    screenshot = requests.get(screenshotURL)
    outfileName = domain.replace(".", "_")
    if(os.path.isdir("resultpng")) == False:
        os.mkdir("resultpng")
    with open("resultpng/"+outfileName+".png", "wb") as f:
        f.write(screenshot.content)
    #URLの判定結果とサイト内リンク一覧を返す
    if(domain == resultParser._effectiveDomain):
        print(domain + ": ")
    else:
        print(resultParser._effectiveDomain + " (submitted: " + domain + "): ")
    print("     " + resultParser._verdictResult.replace("\n", ""))
    print("     This site has " + str(len(resultParser._inSiteLinkDomains)) + " link domain:    ", end='')
    for i, inSiteLink in enumerate(resultParser._inSiteLinkDomains):
        if i == len(resultParser._inSiteLinkDomains)-1:
            print(inSiteLink)
        else:
            print(inSiteLink + ", ", end="")
    print()
    return

#URLを解析する
def scanningLinkDomeins(linkDomain):
    print("\n--------------urlscan.io--------------")
    domainList = list(linkDomain) #結果取得時に順序を考慮するためリストにする
    resultURLs = []
    for domain in domainList:
        res = scanRequest(domain)
        if res.status_code == 200:  #正常に解析ができた場合は結果のリンクをリストに加える
            resultURL = res.json()["result"]
            resultURLs.append(resultURL)
        else:   #正常な解析ができなかった場合は返ってきたステータスコードをリストに加える
            resultURLs.append(res.status_code)
    time.sleep(15) #postして即座に解析情報をリクエストすると結果が見つからないためしばらく待つ
    for i in range(len(domainList)):
        if isinstance(resultURLs[i], int) == True:
            print(domainList[i] + ": ")
            print("     " + str(resultURLs[i]) + "\n")
        else:
            accessResult(resultURLs[i], domainList[i])
    return
