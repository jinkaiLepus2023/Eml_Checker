import requests
import json
import time
from html.parser import HTMLParser

#分析結果のHTMLから必要な情報(現段階ではURLの判定結果とスクリーンショットの2つ)を抽出
class ResultParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._in_h4 = False
        self._in_region = False
        self._screenshotURL = ""
        self._verdictResult = ""

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            if attrs[0][1] == "screenshot":
                self._screenshotURL = attrs[1][1]
        if tag == "h4":
                self._in_h4 = True

    def handle_endtag(self, tag):
        if tag == "h4":
            self._in_h4 = False
            self._in_region = False

    def handle_data(self, data):
        if self._in_region == True:
            self._verdictResult += data
        if self._in_h4 == True:
            if data == "urlscan.":
                self._in_region = True
                self._verdictResult += data


#URLをurlscan.ioに投げて解析結果を取得する
def scanningLinkDomein(domain):
    #urlscan.io API要求を作成してpost，リンクのドメイン部分を解析してもらう
    headers = {'API-Key':'55ee3921-d101-4aeb-ade6-97e4f51379ca','Content-Type':'application/json'}
    data = {"url": domain, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan',headers=headers, data=json.dumps(data))
    responseD = response.json()
    if response.status_code != 200:
        #正常にアクセス出来なかった場合はエラーログを返す
        return str(responseD)
    else:
        #正常にアクセスできた場合は解析結果のURLにアクセスして解析情報を取得する
        time.sleep(15) #postして即座に解析情報をリクエストすると404になるためしばらく待つ
        resultURL = responseD["result"]
        resultHtml = requests.get(resultURL)
        resultParser = ResultParser()
        resultParser.feed(resultHtml.text)
        #スクリーンショットはresultpngディレクトリ内に「URL.png」というファイル名で保存
        screenshotURL = "https://urlscan.io" + resultParser._screenshotURL
        screenshot = requests.get(screenshotURL)
        outfileName = domain.replace(".", "_")
        with open("resultpng/"+outfileName+".png", "wb") as f:
            f.write(screenshot.content)
        #URLの判定結果を返す
        return resultParser._verdictResult.replace("\n", "")

"""動作確認用
def main():
    linkDomain = "www.deepl.com" # No Classification
    linkDomain = "xtremedevelopers.com" # Potentially Malicious
    scanningLinkDomein(linkDomain)


if __name__ == "__main__":
    main()
"""
