anonysql.ini
　設定ファイル
　[Anonysql client 1.0]
　AuthentServerAddr=(認証サーバ名):(ポート番号)
　AuthentServerPubKey=(認証サーバの公開鍵のファイル名)
　DataServerAddr=(データサーバ名):(ポート番号)
　DataServerPubKey=(データサーバの公開鍵のファイル名)
　DataServerName=（データサーバ名）
　DatabaseName=(データベース名)
　MyName=（クライアント名）
　MyKey=（クライアントの秘密鍵のファイル名）
　GunshuManager=(Gunshuマネージャサーバ名):(ポート番号)
　GunshuLimit=（Gunshu最大転送段数、０を指定するとサーバと直接接続）
　CertStoreDataSource=（レコード所有者証明書ストアのODBCデータソース名）
　CertStoreUID=（レコード所有者証明書ストアのODBCユーザ名）
　CertStorePWD=（レコード所有者証明書ストアのODBCパスワード名）

denpaprv.key
　クライアントの秘密鍵（MiniSSLクライアント認証用）

Debug/metaquery.exe
　実行ファイル

authentpub.key
　認証サーバの公開鍵（MiniSSLサーバ認証用）
datastorepub.key
　データサーバの公開鍵（MiniSSLサーバ認証用）

authority/(権限コード).key
　リクエスト証明書検証用の公開鍵

anonysqlclient.c
anonysqllib.h
　匿名データベースクライアント用のライブラリ

certstore.c
　レコード所有者証明書ストア関連の関数群

digisign.c
　ブラインド署名、RSA署名関連関数群

main.c
　エントリポイント

proc.c
　リンクエラー回避のためにあるだけ