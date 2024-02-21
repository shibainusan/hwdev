authentprv.key
　認証サーバの秘密鍵。（MiniSSLサーバ認証用）

acl/
　クライアントのアクセス許可リストを格納するフォルダ

acl/acl.txt
　(クライアント名),(権限コード)

acl/(クライアント名).key
　クライアント認証に使う公開鍵

authority/
　権限コードに対応する秘密鍵を格納するフォルダ

authority/（権限コード）.key
　リクエスト証明書生成用の秘密鍵

Debug/authent.exe
　実行ファイル

anonysql.h
　匿名データベース各モジュール共通で参照されるヘッダファイル

main.c
　プログラムのエントリポイント

proc.c
　スレッドルーチン