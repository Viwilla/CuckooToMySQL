# CuckooToMySQL
批量提取cuckoo检测信息到数据库
# CukooToMySQL
    开发环境:python2.7 + scapy + cuckooCentOS
    程序功能:批量提取cuckoo检测信息到数据库
    DB TABBLE:
    CREATE TABLE `samplesinfo` (
      `ID` int(11) NOT NULL,
      `SampleSHA1` varchar(40) NOT NULL,
      `SampleMD5` varchar(32) DEFAULT NULL,
      `SampleType` text,
      `SamplePacker` text,
      `360AV` text,
      `Avira` text,
      `ClamAV` text,
      `Eset` text,
      `F_Secure` text,
      `Kaspersky` text,
      `Symantec` text,
      `Yara` text,
      `DNS_IP` text,
      `IP_Port` text,
      `Flow` text,
      PRIMARY KEY (`ID`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;




    自觉写程序的经验不足,有错误或可以优化的地方希望大家不吝赐教。
    希望我的小程序对您有帮助~~^＿＾


    Development Environment: python2.7 + scapy + cuckoo CentOS
    Function: Extraction the information detected by cuckoo to the database
    If there are any errors I hope you feel free to advise.Thanks!
    Hope my little program is useful to you~~ ^ _ ^
