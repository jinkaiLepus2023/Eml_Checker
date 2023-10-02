import sys
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import re
from spamcheck import *
#emlから送信元メールアドレス部分のドメインと
#本文に添付されたリンクのドメイン部分を抜き出す(対フィッシング)
#使い勝手を考えてD&Dで起動...は面倒そうなので引数に指定して実行


url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

#メールアドレスのドメイン部分を抜き出す
def extract_MailAddress_Domain(file):
    mail_domain =""
    with open(file,'rb') as eml:
        #emlの読み込み&パース
        msg = BytesParser(policy=policy.default).parse(eml)
        #送信元アドレスの抽出
        address = email.utils.parseaddr(msg['From'])[1]
        #＠以降が欲しいのでsplitで分割
        if "@" in address:
            mail_domain = address.split("@")[1]
    return mail_domain

#リンクのドメイン部分を抜き出す
def extract_Link_Domain(file):
    #重複対策でsetに
    link_domain = set([])
    #ファイルの読み込み
    with open(file,'rb') as eml:
        msg = BytesParser(policy=policy.default).parse(eml)
        #本文部分，text/htmlのとき抜き出す.text/plainはどうしよう...
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                content = part.get_payload(decode=True).decode(part.get_content_charset() ,'ignore')
                #正規表現でurlを取り出す hrefのとこだけ
                ex_urls = re.findall(url_pattern, content)
                #ドメイン部分を抜き出す [0]が最初のなので偶数番目がhrefのはず
                for link in ex_urls:
                    #要素が偶数のときhrefの中身
                    if ex_urls.index(link) % 2 == 0: 
                        link_domain.add(urlparse(link).netloc)
    return link_domain

def main(filePath):
    mailAddressDomain = extract_MailAddress_Domain(filePath)
    linkDomain = extract_Link_Domain(filePath)
    #print("mail address domain :" + mailAddressDomain)
    check_zenbl(mailAddressDomain)
    #abuseIPDBを使うなら↓
    #abuse_check(mailAddressDomain)

    for domain in linkDomain:
        print("link domain :" + domain)


    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage : python extract.py file(.eml)")
        sys.exit()
    else:
        main(sys.argv[1])