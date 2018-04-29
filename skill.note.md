# HAProxy

kernel參數要修改:

    vim /etc/sysctl.conf
      net.ipv4.ip_nonlocal_bind = 1
    :wq

此參數是為了讓空介面也可以bind ip
是為了讓haproxy 有HA做用的。


# Netdatay資料送到influxdb

編輯netdata設定檔:

    vim /opt/netdata/etc/netdata/netdata.conf
      [backend]
      enabled = yes
      data source = average
      type = opentsdb
      destination = localhost
      prefix = netdata
    :wq

    systemctl restart netdata

編輯influxdb設定檔:

    vim /etc/influxdb/influxdb.conf
      [[opentsdb]]
      enabled = true
    :wq

    systemctl restart influxdb

參考:

    https://github.com/firehol/netdata/wiki/netdata-backends


# icinga自定義cmd_by_ssh

編輯config.php

    vim config.php
      <?php
      $host = '10.1.1.1';
      $user = 'root';
      $passwd = 'root';

      $fn = '/opt/icinga/custom/cmd_by_ssh.log';

      $policy['DOWN'] = <<<Policy
      config router policy
        edit 20
          set input-device internal
          set src 0.0.0.0/0
          set dst 10.0.0.1/255.255.255.0
          set gateway 10.0.0.2
          set output-device wan1
        next
      end
      Policy;

      $policy['UP'] = <<<Policy
      config router policy
      delete 20
      Policy;

      ?>
    :wq


編輯cmd_by_ssh.php

    vim cmd_by_ssh.php

    <?php
    include 'config.php';

    function get_connection()
    {
      global $host;
      global $user;
      global $passwd;
      global $fp;

      $conn = ssh2_connect($host, 22);
      if(ssh2_auth_password($conn,$user,$passwd))
      {
        echo 'success'."\n";
        fwrite($fp, date(DATE_RFC2822).': success'."\n")
      }else{
        echo 'fail'."\n";
        fwrite($fp, date(DATE_RFC2822).': fail'."\n")
      }

      return $conn;

    }



    ?>


# PostgreSQL(yum版本)

1.Install yum repo

2.Check `postgresql client` 是否安裝

移除作業系統預設自帶的版本

    yum remove postgresql postgresql-devel postgresql-libs

3.使用yum安裝PostgreSQL

    postgresql9x          client 連線工具

    postgresql9x-server   service

    postgresql9x-contrib  提供pg_archivecleanup工具

4.PostgreSQL初始化

    centos6:

      /etc/init.d/postgresql-9.x initdb

5.變更postgresql設定檔
postgresql 預設安裝位置為 /var/lib/pgsql/9.x/
設定檔案位置為 /var/lib/pgsql/9.x/data/

編輯 postgresql.conf

    vim /var/lib/pgsql/9.x/data/postgresql.conf
    # 監聽所有連線，預設是localhost 只能監聽本機連線，外部無法連上
    listen_addresses = '*'

編輯 pg_hba.conf

    vim /var/lib/pgsql/9.x/data/pg_hba.conf
    # 允許10.0.0.0/16 使用任何帳號存取任何資料庫 密碼使用md5加密
    # type  DATABASE   USER   ADDRESS       METHOD
      host  all        all   [ip/netmask]   md5

6.建立root帳號
切斷到postgres來進行
postgres@host# creatuser -P -s -d -l -r root

    # createuser 是 postgresql client 工具之一 用來建立資料庫使用者
    # -P 建立密碼
    # -s 提供superuser權限
    # -d 提供建立資料庫權限
    # -r 提供建立帳號權限
    # -l 提供登入權限

    postgres@host# createdb -O root root
    # postgresql 的機制 每個使用著都必須擁有對應的資料庫纔能夠登入操作

7.啟動postgresql

    /etc/init.d/postgresql-9.x restart
    chkconfig postgresql-9.x on


# Postgresql install with compiler

## 1. 下載 source code
官網下載要安裝的版本

## 2. 檢查 `postgresql client` 是否已被安裝?
由於 rhel/centos 原始安裝源也有 postgresql
所以有時候預設會安裝 postgresql client
需要先移除 postgresql client

` root@host# yum remove postgresql postgresql-devel postgresql-libs`

## 3. 編譯安裝 postgresql
首先解壓縮並進入目錄

編譯安裝 postgresql
`root@host# ./configure --prefix=/var/lib/pgsql`
` root@host# make`
`root@host# make install`


預設安裝目錄為 /usr/local/pgsql
然而本例事先已經將大部分磁碟空間分配給 /var
所以需指定安裝目錄到 /var 底下
--prefix  參數指定安裝目錄


## 4. 設置 postgres 權限
`root@host# useradd postgres`
`root@host# chown -R postgres:postgres /var/lib/pgsql`

編輯 `/etc/passwd` 將 postgres 家目錄改為 `/var/lib/pgsql`

    # 不要照貼，只要修改家目錄的部分就好
    postgres:x:500:500::/var/lib/pgsql:/bin/bash

`root@host# cp -a /home/postgres/.bash* /var/lib/pgsql`

## 5. 資料庫初始化
切換到 postgres 來進行
`postgres@host$ /var/lib/pgsql/bin/initdb -D /var/lib/pgsql/data`

    -D 指定資料庫資料存放的目錄，一般會放置在 postgresql 安裝目錄下的 data


## 6. 編輯設定檔
### 複製 postgresql.conf
`root@host# cp -a /var/lib/pgsql/data/postgresql.conf /var/lib/pgsql/data/postgresql.conf.bak`
`root@host# cat /root/postgresql.conf > /var/lib/pgsql/data/postgresql.conf `

### 遠端連線設定
編輯 pg_hba.conf
`root@host# vim /var/lib/pgsql/data/pg_hba.conf`

    #  遠端連線密碼請使用 md5 加密
    #    TYPE  DATABASE        USER            ADDRESS                 METHOD
    host    all             all             [ip/netmask]             md5


    # postgresql.conf 及 pg_hba.conf 如果是複製過來的，檔案 owner 須改為 postgres


## 7. 將官方程式加入 PATH
編輯 /etc/profile
`root@host# vim /etc/profile`

    # 最後加入這行
    PATH=$PATH:/var/lib/pgsql/bin


## 8. 設定開機啟動
複製開機啟動 script 至 /etc/init.d/postgresql
`root@host# cp -a /root/postgresql /etc/init.d/postgresql`
`root@host# /etc/init.d/postgresql start`
`root@host# chkconfig --add postgresql`
`root@host# chkconfig postgresql on`

## 9. 建立 root 帳號及資料庫
    切換到 postgres 來進行
    `postgres# createuser -P -s -d -l -r root`

    #  createuser 是 postgresql client 工具之一，用來建立資料庫使用者
    #  -P  建立密碼
    #  -s  提供 superuser 權限
    #  -d  提供建立資料庫權限
    #  -r  提供建立帳號權限
    #  -l  提供登入權限

`postgres# createdb -O root root`

    #  postgresql 的機制，每個使用者都必須擁有對應的資料庫才能夠登入操作


# 檢查rsyslog, syslog檔案是否存在

    #!/bin/bash
    if [ -f /etc/rsyslog.conf ] ; then
    {
      sed -i 's/10.0.0.1/10.0.0.2/g' /etc/rsyslog.conf
      echo "*.* @logserver_ip" >> /etc/rsyslog.conf
      service rsyslog restart
    }


# 抓取主機SN

    dmidecode | grep "Serial Number" | egrep '([a-zA-Z0-9]){7}$' | awk '{print $3}'


# fail2ban

主要設定檔

    /etc/fail2ban/fail2ban.conf

設定服務檔

    /etc/fail2ban/jail.conf


# shell script build git

    #!/bin/bash

    yum install wget vim net-tools gcc zlib-devel perl-devel asciidoc xmlto docbook2X -y
    ln -s /usr/bin/db2x_docbook2texi /usr/bin/docbook2x-texi

    wget https://www.kernel.org/pub/software/scm/git/git-2.15.1.tar.gz
    tar zxvf git-2.15.1.tar.gz -C /usr/local/src/

    cd /usr/local/src/git-2.15.1

    ./configure

    make all doc info
    make install install-doc install-html install-info

# pure-ftp user add

    #!/bin/bash

    echo "Please enter your Password : "
    read password

    echo $password >> /tmp/passfile
    echo $password >> /tmp/passfile

    for account in `cat /tmp/list`
    do
    	pure-pw useradd $account -u ftpuser -d /home/ftpuser/file/ -m < /tmp/passfile
    	echo $account add finsh.
    done

    pure-pw mkdb
    rm -f /tmp/passfile

# 開機限制cpu核心使用
Example: CentOS7

    vim /boot/grub2/grub.cfg
      isolcpus=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
    :wq

    taskset -c 1 [command]
    -c 表示要呼叫第幾顆CPU做事情

# 取得xneserver磁碟空間使用率

    for i in `cat list` ; do echo $i ; ssh $i df -h|grep mapper|awk '{print $2,$3,$4,$5}' ; done

# sar

    for i in `ls` ; do sar -f $i -b|grep Ave ; done | cut -d ":" -f 2|awk '{print $5}'

# 計算30天內sar的平均數值 $4,每秒讀 $5,每秒寫

    for i in `ls /var/log/sa/sa[0-9]*` ; do sar -f $i -b|grep Ave ; done | cut -d ":" -f 2|awk '{print $5}' | awk '{sum+=$1} END {print sum/NR}'

# n6200 增加路由指令

    route add host 192.168.57.142 192.168.51.253 1

# Get IBM SN , dell

    dmidecode | grep "Serial Number" | egrep ' ([a-zA-Z0-9]){7}$' | awk '{print $3}' | sort | uniq | grep -v Unknow

    dmidecode | grep x3550 | awk '{print $6}'
    dmidecode | grep x3550 | awk '{print $8}' | cut -d "[" -f 2 | cut -d "]" -f 1

    dmidecode | grep PowerEdge | awk '{print $4}'

    dmidecode | grep "Maximum Capacity"
    dmidecode | grep "Range Size"
    dmidecode | grep "Range Size" | cut -d ":" -f 2 | cut -d " " -f 2-
    dmidecode | grep DDR | wc -l

    cat /proc/cpuinfo|grep Xeon| uniq| cut -d ":" -f 2- | cut -d " " -f 2-


# 中文亂碼解決方案

    cd /usr/java/jdk1.6.0_26/jre/lib/fonts //ㄎ進入目前所使用的java版本資料夾
    mkdir fallback
    將中文自行複製到fallback資料夾裡面即可

# 在history上 加上時間


    vim /etc/profile
        HISTTIMEFORMAT='<%F %T>:'
        export HISTTIMEFORMAT
    :wq

# 解決vnc一直跳出視窗要要求更新

    sed -i 's/<allow_any>auth_admin<\/allow_any>/<allow_any>no<\/allow_any>/g'   /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
    sed -i 's/<allow_inactive>auth_admin<\/allow_inactive>/<allow_inactive>no<\/allow_inactive>/g'   /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy

# 使用sed讀取某個檔案的某一行

    sed -n '1,1p' [filepath]
    //讀取檔案的第一行

# 透過inotifywait監控檔案系統

    yum install inotify-tools -y
    inotifywait -mrq -e create,close,open /root

# 關閉tomcat版本資訊

    for i in $(seq 15 23) $(seq 35 40) 50 $(seq 86 90) $(seq 112 113)
    do
        ssh 10.3.12.$i "su - tomcat -c 'mkdir -p /opt/tomcat/lib/org/apache/catalina/util'"
    done

    for i in $(seq 15 23) $(seq 35 40) 50 $(seq 86 90) $(seq 112 113)
    do
        echo $i ;ssh 10.3.12.$i "su - tomcat -c 'echo "server.info=Apache Tomcat Version X" >> /opt/tomcat/lib/org/apache/catalina/util/ServerInfo.properties'"
    done

# 關閉apache版本資訊

    # ServerTokens
    # This directive configures what you return as the Server HTTP response
    # Header. The default is 'Full' which sends information about the OS-Type
    # and compiled in modules.
    # Set to one of:  Full | OS | Minor | Minimal | Major | Prod
    # where Full conveys the most information, and Prod the least.
    #
    ServerTokens Prod


    # Optionally add a line containing the server version and virtual host
    # name to server-generated pages (internal error documents, FTP directory
    # listings, mod_status and mod_info output etc., but not CGI generated
    # documents or custom error documents).
    # Set to "EMail" to also include a mailto: link to the ServerAdmin.
    # Set to one of:  On | Off | EMail
    #
    ServerSignature Off

# iostat 參數

    iostat
        -h
        -n

# find

    find /root/21/*/00 -maxdepth 1 -name 000 -exec mv {} {}_new  \;


# netapp storage extend indoe

    maxfiles [volname] [indoe]

# qnap command

    cat /proc/mdstat

    mdadm -D /dev/md1

    cat /proc/sys/dev/raid/speed_limit_max

    cat /proc/sys/dev/raid/speed_limit_min


# pure-ftp

    vim passfile

        password
        password

    :wq


    for i in `cat /tmp/list`
    do
        pure-pw useradd $i -u ftpuser -d /home/ftpuser/file/ -m < /tmp/passfile
    done

    pure-pw mkdb

# Get xenserver vm ip

        xe vm-list params=name-label,networks | grep ip | awk '{print $4}' | cut -d ";" -f 1 | sort

# Get partitions

    cat /proc/partitions | sort | awk '{print $4}' | head -n 3 | tail -n 1

# import java cert

    keytool -import -file /home/tomcat/root.cer -keystore cacerts -alias server -keypass changeit -storepass changeit
    keytool -import -noprompt -trustcacerts -alias startssl -file /home/tomcat/root.cer -keystore "/usr/java/jdk1.6.0_45/jre/lib/security/cacerts" -keypass changeit -storepass changeit


# 如何判斷主機是否為 實體主機/虛擬機

    lscpu|grep Hypervisor| awk '{print $3}' ; lscpu|grep Virtualization|awk '{print $3}'

    ssh root@host "lscpu|grep Hypervisor && lscpu|grep Virtualization"
    Hypervisor vendor:     Xen
    Virtualization type:   none


# redis

    $ sudo su -
    # service redis-sentinel stop
    # vi /etc/redis/sentinel.conf


    sentinel monitor <sentinel-name> <master host ip> 6379 2
    sentinel config-epoch <sentinel-name> 0
    sentinel leader-epoch <sentinel-name> 0

    -- 清除myid訊息
    sentinel myid  ............

    sentinel known-slave ..............
    sentinel known-sentinel ...................


    # service redis-sentinel start


    $ sudo su -
    # redis-cli -p 26379
       > sentinel master <sentinel_name>
       > sentinel slaves <sentinel_name>

# XenServer updata PATH

    #/bin/bash

    export PATH=/opt/xensource/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin

    /etc/init.d/iptables stop
    chkconfig iptables off

    /etc/init.d/snmpd start
    chkconfig snmpd on

    sh /opt/xensource/packages/files/transfer-vm/install-transfer-vm.sh
    echo "*/1 * * * * /bin/sh /root/checkXAPI.sh" >> /var/spool/cron/root

    for i in $(ls *.xsupdate)
    do
        xe patch-upload file-name=/root/$i -u root -pw 1234Asdf >> xeuuid
    done


    for i in $(cat xeuuid)
    do
        xe patch-apply host-uuid=$(xe host-list | grep uuid | cut -d ":" -f 2 | cut -d " " -f 2) uuid=$i
    	#pool master only use.
    	#xe patch-pool-apply host-uuid=$(xe host-list | grep uuid | cut -d ":" -f 2 | cut -d " " -f 2) uuid=$i
    done

    rm -rf XS65E*
    rm -rf xe*
    #reboot


# python check backup yes or no and send mail

    import os
    import re
    import datetime
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    today = datetime.date.today()

    logdir = 'C:\\Program Files (x86)\\FileZilla Server\\Logs\\'
    logfile = logdir+'fzs-'+str(today)+'.log'
    tempfile = logdir+'tlog-'+str(today)+'.log'


    def sendalert():
      fromaddr = 'noreply@fmt.com.tw'
      toaddr = ['eric@eric.com']
      cc = ['eric@eric.com']
      subject = 'ERROR - svn 備份發生異常'

      host = '10.x.x.x'

      msg = MIMEMultipart()
      msg['From'] = fromaddr
      msg['To'] = ','.join(toaddr)
      msg['Subject'] = subject
      msg['Cc'] = ', '.join(cc)


      body = '詳情請參閱附件。'

      msg.attach(MIMEText(body, 'plain'))

      with ropen(tempfile) as fd:
        attachment = MIMEText(fd.read(), 'plain')

      attachment.add_header('Content-Disposition', 'attachment', filename = 'tlog-'+str(today)+'.log')

      msg.attach(attachment)
      text = msg.as_string()
      toaddrs = toaddr + cc

      server = smtplib.SMTP(host, 25)
      server.sendmail(fromaddr, toaddrs, text)
      server.quit()

    def ropen(fn):
      fd = open(fn, 'r', encoding='UTF-8', newline='\r\n')
      return fd

    def wpopen(fn):
      fd = open(fn, 'w+', encoding='UTF-8')
      return fd

    def exist_err_code():
      res = 0
      with ropen(logfile) as fd:
        for ll in fd:
          line = fd.readline()
          if re.search("tsmsvn(.*)> (4|5)[0-9]{2}", line):
            res = 1
            break

      return res

    def is_svn_bak():
      res = 0

      with ropen(logfile) as fd:
        for ll in fd:
          line = fd.readline()
          if re.search("tsmsvn", line):
            res =1
            break

      return res

    def save_err_log():
      lf = ropen(logfile)
      tf = wpopen(tempfile)

      for ll in lf:
        line = lf.readline()
        if re.search("tsmsvn(.*)> (4|5)[0-9]{2}", line):
          tf.write(line)

      lf.close()
      tf.close()
      return 0


    if exist_err_code():
      save_err_log()
      sendalert()
      os.remove(tempfile)
    else:
      if not is_svn_bak():
        with wpopen(tempfile) as tfd:
          tfd.write('本日 svn 沒有備份紀錄')

        sendalert()
        os.remove(tempfile)


# 在nginx上設定https

## 1.產生憑證

建立放置憑證的目錄:

    mkdir -p /usr/local/nginx/SSL


產生憑證:

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /usr/local/nginx/ssl/nginx.key -out /usr/local//nginx/ssl/nginx.crt


以下是這裡使用到的參數與簡略說明：

    req：使用 X.509 Certificate Signing Request（CSR） Management 產生憑證。

    -x509：建立自行簽署的憑證。

    -nodes：不要使用密碼保護，因為這個憑證是 NGINX 伺服器要使用的，如果設定密碼的話，會讓伺服器每次在啟動時書需要輸入密碼。

    -days 365：設定憑證的使用期限，單位是天，如果不想時常重新產生憑證，可以設長一點。

    -newkey rsa:2048：同時產生新的 RSA 2048 位元的金鑰。

    -keyout：設定金鑰儲存的位置。

    -out：設定憑證儲存的位置。

這裡我們會同時建立憑證與金鑰，建立的過程中會需要填寫一些基本的資料：

    Country Name (2 letter code) [AU]:TW     國家代碼，台灣就填 TW。
    State or Province Name (full name) [Some-State]:Taiwan     州或省，台灣就填 Taiwan。
    Locality Name (eg, city) []:Taipei     城市，例如台北就填 Taipei。
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:My Company      公司名稱。
    Organizational Unit Name (eg, section) []:My Unit      部門名稱。
    Common Name (e.g. server FQDN or YOUR name) []:myhost.gtwang.org     伺服器的 FQDN，這個一定要填寫正確，如果沒有申請網域名稱的話，也可以用 IP 位址替代。
    Email Address []:user@fmt.com.tw     E-mail 信箱。

填寫完成之後，憑證與金鑰的建立就完成了，而存放位置就在 /usr/local/nginx/ssl 目錄中。

## 2. 修改nginx設定檔 增加ssl設定

    vim /usr/local/nginx/conf/nginx.conf

      server {
        listen 80 ;

        # 加入 SSL 設定
        listen 443 ssl;

        # 憑證與金鑰的路徑
        ssl_certificate /usr/local/nginx/ssl/nginx.crt;
        ssl_certificate_key /usr/local/nginx/ssl/nginx.key;

        # ...
      }

    :wq

## 3. 重啟服務

        先查看是如何啟動的 把啟動方式記錄下來:

            ps aux | grep nginx

        然後直接kill掉程序:

            kill pid

        最後在開啓服務:

            /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf


        番外篇：如果很悲劇的nginx沒有外掛ssl模組解決方案
        ========================

        啓動服務時遇到:

            nginx: [emerg] the "ssl" parameter requires ngx_http_ssl_module in /usr/local/nginx/conf/nginx.conf:90

        表示你gg了nginx沒有外掛ssl模組，需要重新編譯nginx。

        ## 1.檢查nginx版本 和 當時編譯的參數

        使用指令檢查：

            /usr/local/nginx/sbin/nginx -V

        輸出結果:

            nginx version: nginx/1.4.7
            built by gcc 4.4.7 20120313 (Red Hat 4.4.7-4) (GCC)

            configure arguments:
              --prefix=/usr/local/nginx
              --user=tomcat
              --group=tomcat
              --add-module=/usr/local/src/ngx_cache_purge-2.1
              --with-http_stub_status_module
              --with-http_gzip_static_module
              --with-http_sub_module
              --with-file-aio
              --with-poll_module



        ## 2. 備份原有設定檔:

            tar zcvf nginx-2017xxxx.tar.gz /usr/local/nginx/

        ## 3. 重新編譯nginx:

        找到原始編譯安裝包:

            cd /usr/locla/src/
            ls
            cd nginx-1.x.x

        我們剛剛已經使用指令找出原本的編譯參數，但這次我們要加上ssl模組。

            --with-http_ssl_module

        所以加上原始的編譯參數會變成這樣:

            ./configure
              --prefix=/usr/local/nginx
              --user=tomcat
              --group=tomcat
              --add-module=/usr/local/src/ngx_cache_purge-2.1
              --with-http_stub_status_module
              --with-http_gzip_static_module
              --with-http_sub_module
              --with-file-aio
              --with-poll_module
              --with-http_ssl_module

        檢查完相依性之後，如果沒有錯誤就直接make:

            make

        使用make install前先將nginx服務停止:

            ps aux | grep nginx
            kill pid

        確認服務被kill:

            ps aux | grep nginx

        由於我們已經備份現有nginx設定檔，所以直接使用make install覆蓋過去即可。

            make install

        編譯完成後啟動nginx:

            /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf

        檢查nginx是否有listen port 443:

            netstat -nltp | grep 443

        # 恭喜完成收工XD

# 安裝MySQL 5.7 Percona版本教學

1.移除現有mysql 並重新安裝percona版本的mysql

      service mysql stop
      yum remove mysql-community-* -y
      rm –rf /var/lib/mysql
      rm –f /var/log/mysqld.log
      rm –f /etc/my.cnf
      userdel –r mysql

        1.停止mysql服務<br>
        2.使用yum移除現有mysql<br>
        3.刪除殘餘mysql的資料庫<br>
        4.刪除mysql的log檔<br>
        5.刪除mysql的設定檔<br>
        6.移除mysql的user<br>

        ### 移除乾淨之後就可以往下個步驟 ，安裝Percona

         2.安裝Percona
        ==============
        安裝Percona的repo源<br>

            yum install http://www.percona.com/downloads/percona-release/redhat/0.1-3/percona-release-0.1-3.noarch.rpm

        yum安裝Percona<br>

            yum install Percona-Server-server-57 -y

        以下是基本會安裝的套件:

            Percona-Server-server-57
            Percona-Server-client-57
            Percona-Server-shared-57

        啟動mysql:

            service mysql start

        第一次啟動初始化mysql後，第一次登入的密碼會寫mysql的log檔裡面，所以:

            cat /var/log/mysqld.log | grep password

        這邊可以找到password寫在這邊

            2016-08-18T01:23:18.609863Z 1 [Note] A temporary password is generated for root@localhost: cj%+s,Egp8an

        接下來就可以拿這密碼進行初始化設定:

            mysql_secure_installation

        1.輸入第一次登入的密碼<br>
        2.換新的密碼(須遵守密碼原則英文大小寫,數字,特殊字元,共12位)<br>
        3.然後開始回答一連串的初始設定問題<br>

        	Securing the MySQL server deployment.

        	Enter password for user root:

        	The existing password for the user account root has expired. Please set a new password.

        	New password:

        	Re-enter new password:

        	Estimated strength of the password: 100
        	Do you wish to continue with the password provided?(Press y|Y for Yes, any other key for No) : y
        	By default, a MySQL installation has an anonymous user,
        	allowing anyone to log into MySQL without having to have
        	a user account created for them. This is intended only for
        	testing, and to make the installation go a bit smoother.
        	You should remove them before moving into a production
        	environment.

        	Remove anonymous users? (Press y|Y for Yes, any other key for No) : y
        	Success.


        	Normally, root should only be allowed to connect from
        	'localhost'. This ensures that someone cannot guess at
        	the root password from the network.

        	Disallow root login remotely? (Press y|Y for Yes, any other key for No) : y
        	Success.

        	By default, MySQL comes with a database named 'test' that
        	anyone can access. This is also intended only for testing,
        	and should be removed before moving into a production
        	environment.


        	Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
        	 - Dropping test database...
        	Success.

        	 - Removing privileges on test database...
        	Success.

        	Reloading the privilege tables will ensure that all changes
        	made so far will take effect immediately.

        	Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y
        	Success.

        	All done!

        設定完成就可以進行登入:

            mysql -u root -p

        嘗試執行一個mysql指令試試看:

            mysql> show databases;

        如果有正常show出databases那就是沒問題了。<br/>

        3.題外話
        ==============
        ### 降低密碼的policy原則<br>
        編輯/etc/my.cnf:

            vim /etc/my.cnf
               [mysql]
                validate_password_policy=LOW
            :wq

            service mysql restart

        這樣就降低了密碼的policy原則<br>
         or
        登入mysql後
        mysql> set global validate_password_policy=LOW;

        ### 密碼永遠不過期
        針對root帳號設定，密碼永遠不過期<br>

            mysql> use mysql;
            mysql> alter user root@localhost expire never;

        ### mysql密碼忘記的救援方式
        編輯vim /etc/my.cnf:

            vim /etc/my.cnf
                skip-grant-tables
            :wq

            service mysql restart
        或<br>

            mysqld_safe --skip-grant-tables &

        這樣就可以直接登入mysql，然後修改密碼。

            mysql -u root
            mysql> use mysql;
            mysql> alter user 'root@localhost' identified by 'newpassword';
            mysql> flush privileges;
            mysql> quit

        修改完成之後，記得把/etc/my.cnf的skip-grant-tables拿掉<br>
        再重新啟動mysql服務。<br>
