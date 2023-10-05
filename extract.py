import sys
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import re
from spamcheck import *
from scanLinkDomain import *
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

def server_check(filePath):
    with open(filePath, "r", encoding="utf-8") as eml_file:
        msg = email.message_from_file(eml_file)
        #ヘッダのDKIMとSPFについて取得
        dkim_header = msg.get('DKIM-Signature')
        spf_header = msg.get('Received-SPF')
    # Receivedヘッダを取得して、メールホップ情報を表示
    if "Received" in msg:
        received_headers = msg.get_all("Received")
        for i, received_header in enumerate(received_headers, start=1):
            print(f"Received Hop {i}:\n{received_header}\n")
    if dkim_header:
        print("dkim : "+dkim_header)
    if spf_header:
        print("spf : "+spf_header)
    else:
        print("Received headers not found in the email.")
        eml_file.close()


def main(filePath):
    server_check(filePath)
    mailAddressDomain = extract_MailAddress_Domain(filePath)
    linkDomain = extract_Link_Domain(filePath)
    #print("mail address domain :" + mailAddressDomain)
    check_zenbl(mailAddressDomain)
    server_check(filePath)

    print("\n", end="")
    for domain in linkDomain:
        print("link domain :" + domain)
    scanningLinkDomeins(linkDomain)


def main_light(filePath):
    mailAddressDomain = extract_MailAddress_Domain(filePath)
    check_zenbl(mailAddressDomain)
    server_check(filePath)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage : python extract.py file(.eml)")
        sys.exit()
    #第二引数に-lがあった時，spamcheckだけ走る(誰でも手軽に)
    elif len(sys.argv) >=3 and sys.argv[2] == "-l":
        main_light(sys.argv[1])
    else:
        main(sys.argv[1])
