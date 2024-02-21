authority/(権限コード).key
　リクエスト証明書検証用の公開鍵

Debug/datastore.exe
　実行ファイル

anonysql.ini
　データサーバの設定ファイル。　
　レコード所有者証明書を生成するときに使う。
　MyName= (サーバ名)
　DatabaseName=(データベース名)

datastoreprv.key
　データサーバの秘密鍵（MiniSSLサーバ認証用）
　
recordownerdes.key
　レコード所有者証明書生成用DES鍵
　DES56bit+パリティ8bit+初期化ベクタ64bit

odbclib.ini
　ODBCデータベース接続の設定

proc.c
　スレッドルーチン。各SQL文の処理。

profiler.c
profiler.h
　性能計測用関数群

sql.c
　SQL文の文字列処理
　