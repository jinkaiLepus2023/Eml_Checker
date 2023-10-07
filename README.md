# LeParser(りーぱーさー)
emlの調査を半自動化!!

# 機能
emlファイルの  
1送信元のドメインの表示  
2ホップの表示  
3SPF,DKIMの表示  
4spamhausブラックリストに入っているかの表示  
5本文のリンクのドメイン部分をurlscan.ioで調査(要APIキー)  

# 使い方
1.python LeParser.py hogehoge.eml -l  
こちらは機能の1,2,3,4のみ．APIキー要らずですぐに使える  

2python LeParser.py hogehoge.eml  
こちらは1~5のすべての機能を使用可能.APIキーをscanLinkDomain.pyの61行目に書く必要あり．  

