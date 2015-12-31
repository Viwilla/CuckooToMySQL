#----------------------------------------------------
#数据库连接在235行，注意端口不要用引号
#linux下跑可能会遇到编码问题，请去掉我的中文注释
#_author_ = Vi
#https://github.com/Viwilla
#http://www.cnblogs.com/Viwilla/
#eamil:3320163319@qq.com
#----------------------------------------------------
#_author_ = Vi
import json
import codecs
import sqlite3
import os,sys,os.path
import time
import MySQLdb
import scapy.all as scapy
import binascii
import shutil
reload(sys)
sys.setdefaultencoding('utf-8')
#-----------------------------------------------------------------------------#
#You can use the the following statement if you want to  analysis the HTTP#
#-----------------------------------------------------------------------------#
#try:
    # This import works from the project directory
    #import scapy_http.http
#except ImportError:
    # If you installed this package via pip, you just need to execute this
    #from scapy.layers import http

re = 0
add = 0
ID = 0
global _MD5
totalMD5 = []
strtotal = []
flag = 0
ReFlag = 0

#------------------------------------------------
#ConnectDB(host, user ,paaawd,dbname,port)
#------------------------------------------------
def ConnectDB(h, u ,pa,d,p):
    try:
        global cur
        global conn        
        ISOTIMEFORMAT = '%Y-%m-%d %X'
        conn = MySQLdb.connect(
            host = h, 
            user = u,
            passwd = pa,
            db = d,
            port = p)
        cur = conn.cursor()
        print("use success")
    except :
        print "use DB failed"
#------------------------------------------------
#Find the max ID
#------------------------------------------------
def SelectID():
    str = "SELECT MAX(ID) FROM samplesinfo3"
    global cur
    cur.execute(str)
    ID = cur.fetchall()
    return ID[0][0]
#------------------------------------------------
#Check whether the record already exists or not
#------------------------------------------------
def CountMD5():
    query = "SELECT  SampleMD5 FROM samplesinfo3"
    cur.execute(query)
    md5 = cur.fetchall()
    global totalMD5
    for data in md5:
        #print data[0]
        if data[0] not in totalMD5:
            totalMD5.append(data[0])
#------------------------------------------------
#Analysis the json files
#------------------------------------------------
def ReadJSON(file):
    global ID
    with open(file) as data_file:
        data = json.load(data_file)
    _SHA1 = data['target']['file']['sha1']
    global _MD5
    _MD5  = data['target']['file']['md5']
    if ReFlag == 0:
        if _MD5 not in totalMD5:
            totalMD5.append(_MD5)
        elif _MD5 in totalMD5:
            return 0
    _Type = data['target']['file']['type']
    if not  _Type:
        _Type = ''
    _Yara= data['target']['file']['yara']
    if not _Yara:
        _Yara= ''
    try:
        _360AV = data['virustotal']['scans']['Qihoo-360']['result']
        if not _360AV:
            _360AV = ''
    except:
        _360AV = ''
    try:
        _Avira = data['virustotal']['scans']['Avira']['result']
        if not Avira:
            Avira = ''
    except:
        _Avira = ''
    try:
        _ClamAV = data['virustotal']['scans']['ClamAV']['result']
        if not _ClamAV:
            _ClamAV = ''
    except: 
        _ClamAV = ''
    try:
        _Eset = data['virustotal']['scans']['ESET-NOD32']['result']
        if not _Eset:
            _Eset = ''
    except:
        _Eset = ''
    try:
        _F_Secure = data['virustotal']['scans']['F-Secure']['result']
        if not _F_Secure:
            _F_Secure = ''
    except:
        _F_Secure = ''    
    try:
        _Kaspersky = data['virustotal']['scans']['Kaspersky']['result']
        if not _Kaspersky:
            _Kaspersky = ''
    except:
        _Kaspersky = ''
    try:
        _Symantec = data['virustotal']['scans']['Symantec']['result']
        if not _Symantec:
            _Symantec = ''
    except:
        _Symantec = ''

    str1 = "{}".format(" '%s','%s',\"%s\",'%s','%s','%s','%s','%s','%s','%s','%s',"%(_SHA1, _MD5,_Type, _Yara ,_360AV, _Avira,  _ClamAV , _Eset ,_F_Secure, _Kaspersky, _Symantec))
    return str1
#-------------------------------------------------
#Analysis the pcap files
#-------------------------------------------------
def ReadPcap(file,str0,str1):
    packets = scapy.rdpcap(file)
    for p in packets:
        #print '=' * 78
        #p.show()
        strID = "('%d',"%ID
        _IP = ''
        _dns = ''
        _flow = ''
        if p.payload.name == 'ARP':
            continue
        if p.payload.name == 'IP':
            if p.payload.src == '192.168.229.111':
                # save dst IP
                dst ="dst_%s:%d"%(p.payload.dst, p.payload.payload.dport)
                _IP = dst
            elif p.payload.dst =='192.168.229.111':
                src ="src_%s:%d"%(p.payload.src, p.payload.payload.sport)
                _IP = src

            # TCP protocol        
            if p.payload.proto == 6:       
                if  p.payload.payload.payload.name == 'Raw':
                    load = str(binascii.b2a_hex(p.load))
                    _flow = load
                if  p.payload.payload.payload.name == 'HTTP':
                    if p.payload.payload.payload.payload.name == 'HTTP Response':
                        load = str(binascii.b2a_hex(p.load))
                        _flow = load

            #UDP protoco;
            elif p.payload.proto == 17:
                if  p.payload.payload.payload.name== 'Raw':
                    #ascii = p.load
                    #if ascii not in asciidata:
                        #asciidata.append(ascii)
                    load = str(binascii.b2a_hex(p.load))
                    _flow = load   
                if p.payload.payload.payload.name == 'DNS':
                    dns = p.payload.payload.payload.qd.qname
                    # save dns
                    _dns = dns  
            else:
                print "No rule for protocol %s"%p.payload.proto
                continue
        else:
            print "No rule for %s"%p.payload.name
            continue

        strc = _MD5 + _dns + _IP + _flow 
        if strc not in strtotal:
            strtotal.append(strc)
            str2 = "'%s','%s','%s');"%( _dns, _IP,_flow)             
            _str1 = str0 + strID + str1 +str2
            ToDB(_str1) 
            global flag
            flag = 1 
            continue

    if flag == 0:
        strID = "('%d',"%ID
        str2 = "'%s','%s','%s');"%('','','')
        _str2 = str0 + strID + str1 + str2
        ToDB(_str2)
    return 
#-----------------------------------
#Add the data to Database
#-----------------------------------
def ToDB(_str):
    cur.execute(_str)
    conn.commit()
    global ID
    ID = ID +1
    addstr = " '%s' added"% _MD5
    print addstr
    ReFlag = 1  
    return
#------------------------------------------------
#main()
#------------------------------------------------
def main():
    rootdir = '/root/cuckoo/storage/analyses/'
    n = len(os.listdir(rootdir))
    Js = "reports/report.json"
    pcap = 'dump.pcap'
    if not os.path.exists("pcap"):
        os.mkdir("pcap")
    ConnectDB('ip', 'username', 'pasw', 'dbname', port)
    global ID
    try:
        ID = SelectID() + 1
    except:
        ID = 1
    startID = ID
    str0 = "INSERT INTO samplesinfo3(ID,SampleSHA1, SampleMD5, SampleType, Yara, 360AV, Avira, ClamAV, Eset ,F_Secure, Kaspersky, Symantec,DNS_IP, IP_Port,Flow)values"
    CountMD5()
    for id in range(1,n):
        global ReFlag
        global flag
        file1 = rootdir + '%d/'%id + Js
        file2 = rootdir + '%d/'%id + pcap
        try:
            result = ReadJSON(file1)
            if result == 0:
                print "%s already exists!"%_MD5
                global re
                re = re +1
                continue
            else:
                str1 = result
        except:
            print "ReadJson error!"
        try:
            ReadPcap(file2,str0,str1)
        except:
            flag = 0
            ReFlag = 0
            try:
                print "%s ReadPcap error!"%_MD5
                continue
            except:
                continue
        if flag == 1:
            pcapname = "pcap/%s"%_MD5
            if not os.path.exists(pcapname):
                shutil.copy(file2,pcapname)
            else:
                print "pcap '%s' exists"%_MD5
        flag = 0
        ReFlag = 0

    add = ID - startID
    print "%d items already exists!"%re
    print "Successfully add %d items, from %d to %d ."%(add,startID,ID - 1)
    cur.close()
    conn.close()

if __name__ == '__main__':
    main()

exit()
