# -*- coding: utf-8 -*-
banners = {
    "3cdaemon" : {
        "name" : "3Com 3CDaemon FTP Server 2.0",
        "banner" : "220 3Com 3CDaemon FTP Server Version 2.0",
        "signatures" : {
            "exploit/windows/ftp/3cdaemon_ftp_user( Windows 2000 English )" : "c42a0275",
            "exploit/windows/ftp/3cdaemon_ftp_user( Windows XP English SP0/SP1 )" : "d9eed97424f45b817313",
            "exploit/windows/ftp/3cdaemon_ftp_user( Windows NT 4.0 SP4/SP5/SP6 )" : "99176877",
            "exploit/windows/ftp/3cdaemon_ftp_user( Windows 2000 Pro SP4 French )" : "d0295f77",
            "exploit/windows/ftp/3cdaemon_ftp_user( Windows XP English SP3 )" : "fb41bd7cfb41bd7c"
        }
    },
    "ability" : {
        "name" : "Ability FTP Server 2.34",
        "banner" : "220 Welcome to Ability Server 2.34.",
        "signatures" : {
            "exploit/windows/ftp/ability_server_stor( Windows XP SP2 ENG )" : "cf2ee373",
            "exploit/windows/ftp/ability_server_stor( Windows XP SP3 ENG )" : "5393427e"
        }
    },
    "filecopa" : {
        "name":"FileCOPA FTP Server 1.01",
        "banner":"220−InterVations FileCOPA FTP Server Version 1.01 21st November 2005",
        "signatures" : {
            "exploit/windows/ftp/filecopa_list_overflow":"6681c1a00151c3"
        }
    },
    "freefloatftp" : {
        "name" : "FreeFloat FTP Server 1.00",
        "banner":"220 FreeFloat Ftp Server (Version 1.00).",
        "signatures" : {
            "exploit/windows/ftp/freefloatftp_user" : "81c454f2ffff"
        }
    },
    "sami" : {
        "name" : "Sami FTP Server 2.0.2",
        "banner" : "220 − Sami FTP Server 2.0.2\r\n" + " 220 Feature spa.",
        "signatures" : {
            "exploit/windows/ftp/sami_ftpd_list":"81c454f2ffff"
        }
    },
    "servu" : {
        "name" : "Serv−U FTP Server 4.1.0.3",
        "banner" : "220 − Serv−U FTP Server 4.1.0.3",
        "signatures" : {
            "exploit/windows/ftp/servu_chmod" : "6681caff0f42526a0258cd2e3c055a74efb85730305489d7af75eaaf75e75131c931c002040f41",
            "exploit/windows/ftp/servu_mdtm(Serv−UUber−LeetUniversalServUDaemon.exe)" : "4d44544d2032303033313131313131313131312b41414141414141414141414141414141414141" + "414183c4fc5fbe333332314647393775fb464f3977fc75faffe74242ebe4424277184000202f35333231",
            "exploit/windows/ftp/servu_mdtm(Serv−U4.0.0.4/4.1.0.0/4.1.0.3ServUDaemon.exe)" : "4d44544d2032303033313131313131313131312b41414141414141414141414141414141414141" + "414183c4fc5fbe333332314647393775fb464f3977fc75faffe74242ebe442424d164000202f35333231",
            "exploit/windows/ftp/servu_mdtm(Serv−U5.0.0.0ServUDaemon.exe)" : "4d44544d2032303033313131313131313131312b41414141414141414141414141414141414141" + "414183c4fc5fbe333332314647393775fb464f3977fc75faffe74242ebe442427e164000202f35333231"
        }
    },
    "slimftpd" : {
        "name":"SlimFTPd FTP Server 3.16",
        "banner":"220 − SlimFTPd3.16, by WhitSoftDevelopment (www.whitsoftdev.com)\r\n" + "220 − You are connecting from 127.0.0.1:12345\r\n"+ "220 Proceed with login.",
        "signatures" : {
            "exploit/windows/ftp/slimftpd_list_concat" : "d97424f4"
        }
    },
    "vermillion" : {
        "name":"Vftpd FTP Server 1.31",
        "banner":"220 localhost FTP Server (vftpd1.31) ready.",
        "signatures" : {
            "exploit/windows/ftp/vermillion_ftpd_port" : "2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c3137312c3438"
        }
    },
    "wftpd" : {
        "name" : "WFTPD Pro FTP Server 3.23",
        "banner" : "220 ProFTPD 1.3.1rc2 Server (WFTPD Pro Server 3.23) [ 127.0.0.1 ]",
        "signatures" : {
            "exploit/windows/ftp/wftpd_size" : "d97424f4"
        }
    }
}





