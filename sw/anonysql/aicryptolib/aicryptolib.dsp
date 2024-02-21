# Microsoft Developer Studio Project File - Name="aicryptolib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** 編集しないでください **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=aicryptolib - Win32 Debug
!MESSAGE これは有効なﾒｲｸﾌｧｲﾙではありません。 このﾌﾟﾛｼﾞｪｸﾄをﾋﾞﾙﾄﾞするためには NMAKE を使用してください。
!MESSAGE [ﾒｲｸﾌｧｲﾙのｴｸｽﾎﾟｰﾄ] ｺﾏﾝﾄﾞを使用して実行してください
!MESSAGE 
!MESSAGE NMAKE /f "aicryptolib.mak".
!MESSAGE 
!MESSAGE NMAKE の実行時に構成を指定できます
!MESSAGE ｺﾏﾝﾄﾞ ﾗｲﾝ上でﾏｸﾛの設定を定義します。例:
!MESSAGE 
!MESSAGE NMAKE /f "aicryptolib.mak" CFG="aicryptolib - Win32 Debug"
!MESSAGE 
!MESSAGE 選択可能なﾋﾞﾙﾄﾞ ﾓｰﾄﾞ:
!MESSAGE 
!MESSAGE "aicryptolib - Win32 Release" ("Win32 (x86) Static Library" 用)
!MESSAGE "aicryptolib - Win32 Debug" ("Win32 (x86) Static Library" 用)
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "aicryptolib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x411 /d "NDEBUG"
# ADD RSC /l 0x411 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "aicryptolib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /GX /O2 /Ob2 /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x411 /d "_DEBUG"
# ADD RSC /l 0x411 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "aicryptolib - Win32 Release"
# Name "aicryptolib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\3des.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_cert.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_cmp.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_crl.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_crtp.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_dsa.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_ecc.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_ecdsa.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_ext.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_extdef.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_extmoj.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_file.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_obj.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_p12.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_p7env.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_p7sign.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_pkibd.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_pkihd.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_print.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_req.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_rsa.c
# End Source File
# Begin Source File

SOURCE=.\src\asn1_set.c
# End Source File
# Begin Source File

SOURCE=.\src\base64.c
# End Source File
# Begin Source File

SOURCE=.\src\cert.c
# End Source File
# Begin Source File

SOURCE=.\src\cert_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\cert_ext.c
# End Source File
# Begin Source File

SOURCE=.\src\cert_print.c
# End Source File
# Begin Source File

SOURCE=.\src\cert_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\cert_vfy.c
# End Source File
# Begin Source File

SOURCE=.\src\clist.c
# End Source File
# Begin Source File

SOURCE=.\src\clist_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\cmp.c
# End Source File
# Begin Source File

SOURCE=.\src\cmp_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\cmp_asn1sz.c
# End Source File
# Begin Source File

SOURCE=.\src\crl.c
# End Source File
# Begin Source File

SOURCE=.\src\crl_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\crl_print.c
# End Source File
# Begin Source File

SOURCE=.\src\crl_vfy.c
# End Source File
# Begin Source File

SOURCE=.\src\crtp.c
# End Source File
# Begin Source File

SOURCE=.\src\crtp_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\crtp_print.c
# End Source File
# Begin Source File

SOURCE=.\src\dec_info.c
# End Source File
# Begin Source File

SOURCE=.\src\defalgo.c
# End Source File
# Begin Source File

SOURCE=.\src\des.c
# End Source File
# Begin Source File

SOURCE=.\src\des_asm.c
# End Source File
# Begin Source File

SOURCE=.\src\des_key.c
# End Source File
# Begin Source File

SOURCE=.\src\des_mode.c
# End Source File
# Begin Source File

SOURCE=.\src\digest.c
# End Source File
# Begin Source File

SOURCE=.\src\dsa.c
# End Source File
# Begin Source File

SOURCE=.\src\dsa_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\dsa_gen.c
# End Source File
# Begin Source File

SOURCE=.\src\dsa_key.c
# End Source File
# Begin Source File

SOURCE=.\src\dsa_sig.c
# End Source File
# Begin Source File

SOURCE=.\src\ecc.c
# End Source File
# Begin Source File

SOURCE=.\src\ecc_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\ecc_gen.c
# End Source File
# Begin Source File

SOURCE=.\src\ecc_std.c
# End Source File
# Begin Source File

SOURCE=.\src\ecc_vfy.c
# End Source File
# Begin Source File

SOURCE=.\src\ecdsa.c
# End Source File
# Begin Source File

SOURCE=.\src\ecdsa_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\ecdsa_key.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_addsub.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_conv.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_multi.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_paddsub.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_pmulti.c
# End Source File
# Begin Source File

SOURCE=.\src\ecp_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\error.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_cert.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_crl.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_crlstr.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_crtstr.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_gn.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_moj.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_mojstr.c
# End Source File
# Begin Source File

SOURCE=.\src\ext_pol.c
# End Source File
# Begin Source File

SOURCE=.\src\hmac.c
# End Source File
# Begin Source File

SOURCE=.\src\io.c
# End Source File
# Begin Source File

SOURCE=.\src\key.c
# End Source File
# Begin Source File

SOURCE=.\src\key_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\large_add.c
# End Source File
# Begin Source File

SOURCE=.\src\large_divmod.c
# End Source File
# Begin Source File

SOURCE=.\src\large_exp.c
# End Source File
# Begin Source File

SOURCE=.\src\large_ext.c
# End Source File
# Begin Source File

SOURCE=.\src\large_kara.c
# End Source File
# Begin Source File

SOURCE=.\src\large_karasqr.c
# End Source File
# Begin Source File

SOURCE=.\src\large_long.c
# End Source File
# Begin Source File

SOURCE=.\src\large_mont.c
# End Source File
# Begin Source File

SOURCE=.\src\large_mtcalc.c
# End Source File
# Begin Source File

SOURCE=.\src\large_multi.c
# End Source File
# Begin Source File

SOURCE=.\src\large_prime.c
# End Source File
# Begin Source File

SOURCE=.\src\large_rand.c
# End Source File
# Begin Source File

SOURCE=.\src\large_set.c
# End Source File
# Begin Source File

SOURCE=.\src\large_shift.c
# End Source File
# Begin Source File

SOURCE=.\src\large_sqr.c
# End Source File
# Begin Source File

SOURCE=.\src\large_sqrt.c
# End Source File
# Begin Source File

SOURCE=.\src\large_sub.c
# End Source File
# Begin Source File

SOURCE=.\src\large_sys.c
# End Source File
# Begin Source File

SOURCE=.\src\large_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\lutzrand.c
# End Source File
# Begin Source File

SOURCE=.\src\lutzseed.c
# End Source File
# Begin Source File

SOURCE=.\src\man_add.c
# End Source File
# Begin Source File

SOURCE=.\src\man_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\man_del.c
# End Source File
# Begin Source File

SOURCE=.\src\man_search.c
# End Source File
# Begin Source File

SOURCE=.\src\man_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\manager.c
# End Source File
# Begin Source File

SOURCE=.\src\md2.c
# End Source File
# Begin Source File

SOURCE=.\src\md2c.c
# End Source File
# Begin Source File

SOURCE=.\src\md5.c
# End Source File
# Begin Source File

SOURCE=.\src\md5c.c
# End Source File
# Begin Source File

SOURCE=.\src\mime.c
# End Source File
# Begin Source File

SOURCE=.\src\mime_body.c
# End Source File
# Begin Source File

SOURCE=.\src\mime_head.c
# End Source File
# Begin Source File

SOURCE=.\src\mime_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\mimebd_bin.c
# End Source File
# Begin Source File

SOURCE=.\src\mimebd_msg.c
# End Source File
# Begin Source File

SOURCE=.\src\mimebd_multi.c
# End Source File
# Begin Source File

SOURCE=.\src\mimebd_smime.c
# End Source File
# Begin Source File

SOURCE=.\src\mimebd_txt.c
# End Source File
# Begin Source File

SOURCE=.\src\p12_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\p12_file.c
# End Source File
# Begin Source File

SOURCE=.\src\p12_key.c
# End Source File
# Begin Source File

SOURCE=.\src\p12_mac.c
# End Source File
# Begin Source File

SOURCE=.\src\p12_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\p7_data.c
# End Source File
# Begin Source File

SOURCE=.\src\p7_enc.c
# End Source File
# Begin Source File

SOURCE=.\src\p7_env.c
# End Source File
# Begin Source File

SOURCE=.\src\p7_file.c
# End Source File
# Begin Source File

SOURCE=.\src\p7_sign.c
# End Source File
# Begin Source File

SOURCE=.\src\p7m_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\p7s_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\p7s_attr.c
# End Source File
# Begin Source File

SOURCE=.\src\p8_file.c
# End Source File
# Begin Source File

SOURCE=.\src\pass.c
# End Source File
# Begin Source File

SOURCE=.\src\pbe.c
# End Source File
# Begin Source File

SOURCE=.\src\pbe_cry.c
# End Source File
# Begin Source File

SOURCE=.\src\pbe_key.c
# End Source File
# Begin Source File

SOURCE=.\src\pem.c
# End Source File
# Begin Source File

SOURCE=.\src\pem_cry.c
# End Source File
# Begin Source File

SOURCE=.\src\pem_key.c
# End Source File
# Begin Source File

SOURCE=.\src\pem_msg.c
# End Source File
# Begin Source File

SOURCE=.\src\pem_pkcs.c
# End Source File
# Begin Source File

SOURCE=.\src\pem_w.c
# End Source File
# Begin Source File

SOURCE=.\src\pkcs12.c
# End Source File
# Begin Source File

SOURCE=.\src\pkcs7.c
# End Source File
# Begin Source File

SOURCE=.\src\pkcs8.c
# End Source File
# Begin Source File

SOURCE=.\src\pki_body.c
# End Source File
# Begin Source File

SOURCE=.\src\pki_head.c
# End Source File
# Begin Source File

SOURCE=.\src\pki_msg.c
# End Source File
# Begin Source File

SOURCE=.\src\pkibd_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\pkibd_asn1sz.c
# End Source File
# Begin Source File

SOURCE=.\src\pkihd_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\pkimg_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\rand.c
# End Source File
# Begin Source File

SOURCE=.\src\rc2.c
# End Source File
# Begin Source File

SOURCE=.\src\rc2key.c
# End Source File
# Begin Source File

SOURCE=.\src\rc2mode.c
# End Source File
# Begin Source File

SOURCE=.\src\rc4.c
# End Source File
# Begin Source File

SOURCE=.\src\rc4key.c
# End Source File
# Begin Source File

SOURCE=.\src\req_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\req_vfy.c
# End Source File
# Begin Source File

SOURCE=.\src\rsa.c
# End Source File
# Begin Source File

SOURCE=.\src\rsa_asn1.c
# End Source File
# Begin Source File

SOURCE=.\src\rsa_key.c
# End Source File
# Begin Source File

SOURCE=.\src\sha1.c
# End Source File
# Begin Source File

SOURCE=.\src\signature.c
# End Source File
# Begin Source File

SOURCE=.\src\smime_dec.c
# End Source File
# Begin Source File

SOURCE=.\src\smime_enc.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_alert.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_bind.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_cb.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_cs.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_hello.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_hs.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_hsclnt.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_hskey.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_hsserv.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_list.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_name.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_opssl.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_rand.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_read.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_rec.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_recproc.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_sock.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_vfy.c
# End Source File
# Begin Source File

SOURCE=.\src\ssl_write.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_add.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_del.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_file.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_filemeth.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_search.c
# End Source File
# Begin Source File

SOURCE=.\src\sto_tool.c
# End Source File
# Begin Source File

SOURCE=.\src\store.c
# End Source File
# Begin Source File

SOURCE=.\src\uc_euc.c
# End Source File
# Begin Source File

SOURCE=.\src\uc_jis.c
# End Source File
# Begin Source File

SOURCE=.\src\uc_sjis.c
# End Source File
# Begin Source File

SOURCE=.\src\uc_uni.c
# End Source File
# Begin Source File

SOURCE=.\src\uc_utf8.c
# End Source File
# Begin Source File

SOURCE=.\src\uconv.c
# End Source File
# Begin Source File

SOURCE=.\src\wincry_cert.c
# End Source File
# Begin Source File

SOURCE=.\src\wincry_clist.c
# End Source File
# Begin Source File

SOURCE=.\src\wincry_crl.c
# End Source File
# Begin Source File

SOURCE=.\src\wincry_key.c
# End Source File
# Begin Source File

SOURCE=.\src\x509_file.c
# End Source File
# Begin Source File

SOURCE=.\src\x509_time.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\src\include\aiconfig.h
# End Source File
# Begin Source File

SOURCE=.\src\include\confdefs.h
# End Source File
# Begin Source File

SOURCE=.\src\include\key_type.h
# End Source File
# Begin Source File

SOURCE=.\src\include\large_num.h
# End Source File
# Begin Source File

SOURCE=.\src\include\large_prime.h
# End Source File
# Begin Source File

SOURCE=.\src\lutzpath.h
# End Source File
# Begin Source File

SOURCE=.\src\include\md_global.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_asn1.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_base64.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_cmp.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_des.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_dsa.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_ecc.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_ecdsa.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_err.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_hmac.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_io.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_md2.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_md5.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_mem.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_mime.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_pem.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_pkcs.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_pkcs12.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_pkcs7.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_rand.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_rc2.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_rc4.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_rsa.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_sha1.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_ssl.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_store.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_tool.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_uconv.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_wincry.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_x509.h
# End Source File
# Begin Source File

SOURCE=.\src\include\ok_x509ext.h
# End Source File
# Begin Source File

SOURCE=.\src\include\unicode11.h
# End Source File
# End Group
# End Target
# End Project
