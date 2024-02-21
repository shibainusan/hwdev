CertView095/
　鍵表示用ソフト（名工大製）

client/
　MiniSSLクライアントサンプルアプリ

keygen/
　1024bitRSA＆56bitDES鍵生成アプリ

keygen/Debug/keygen.exe
　実行ファイル

keygen/Debug/prv.key
　RSA秘密鍵(keygen.exeを実行すると生成される)

keygen/Debug/pub.key
　RSA公開鍵(keygen.exeを実行すると生成される)

keygen/Debug/des.key
　DES鍵(keygen.exeを実行すると生成される)

server/
　MiniSSLサーバサンプルアプリ

server/acl/
　クライアントのアクセス許可リストを格納するフォルダ

server/acl/acl.txt
　(クライアント名),(権限コード)

server/acl/(クライアント名).key
　クライアント認証に使う公開鍵

lib/
　MiniSSLライブラリ

lib/minissl.c
　基本送受信関数

lib/minissl.h
　インクルードヘッダ

lib/minissl_client.c
　クライアント用認証関数

lib/minissl_server.c
　サーバ用認証関数

lib/minisslkeyman.c
　鍵管理、ACL読み込み関数など

lib/minissl.lib
　MiniSSLライブラリのバイナリ