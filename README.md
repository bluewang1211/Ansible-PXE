# Deploy PXE Server
這是一個使用在Centos7上使用Ansible部署PXE Server的專案。


# Quick Start

Control Node: Ansible主機

Managed Node: PXE(被部署主機)

### 0. ssh-key-copy

先將Control Node 和 Managed Node完成金鑰驗證。

Control:

    ssh-keygen  //產生key

    ssh-copy-id [ManagedNode IP]  //交換key

### 1. inventory

    vim inventory

      [pxe]
      pxe.example.com ansible_host= 被部署的主機ip

    :wq

### 2. 預設網路環境設定檔，如符合現有網路環境可直接使用。

    defaults/main.yml

### 3. 設定自己的網路環境，vars/main.yml：

    vim vars/main.yml

      # PXE
      pxe_host_ip: 被部署的主機ip ex: 192.168.1.2

      # DHCP
      dhcp_domain_name_server: DHCP要指向的dns server ex: 192.168.1.2
      dhcp_subnet: DHCP要派發的網段 ex: 192.168.1.0
      dhcp_range_start: DHCP派發的起始ip ex: 192.168.1.11
      dhcp_range_end: DHCP派發的結尾ip ex: 192.168.1.20
      dhcp_default_gateway: DHCP派發的gateway ex: 192.168.1.254
      dhcp_next_server: 指向的tftp主機 ex: 192.168.1.2

      # DNS
      dns_example_ip: dns整解的網段 ex:192.168.1
      dns_arpa_ip: dns反解的網段 ex:1.168.192

      # Kickstart
      disk_type: 主機的磁碟代號 ex: sda, vda, xvda ..etc
      dns_ip1: DNS主機1
      dns_ip2: DNS主機2
      ntp_ip1: NTP主機1
      ntp_ip2: NTP主機2
      xen_passwd: xenserver的密碼

    :wq

### 4. setup.yml

依照需求更改網路環境變數檔案。

    vim setup.yml

      vars_files:
        - defaults/main.yml
      #  - vars/main.yml

    :wq    


### 5. 進行部署

    bash start.sh


### 6. 準備所需的ISO

部署完成後登入PXE主機，將ISO掛載至網頁根目錄，提供repo使用。

[Download CentOS 7.4](http://mirror01.idc.hinet.net/CentOS/7.4.1708/isos/x86_64/)

[Download XenServer](https://www.citrix.com/downloads/xenserver/)

網頁根目錄位置：

    /var/www/html/

    html
    ├── centos69  //repo
    ├── centos74  //repo
    ├── ks
    │   ├── centos
    │   └── xenserver
    ├── tools
    └── xenserver72 //repo

### 7. 掛載ISO：

    mount CentOS-7-x86_64-DVD-1708.iso /var/www/html/centos74/

# Reference

[鳥哥：第二章、安裝伺服器與 kickstart 大量部署用戶端電腦](http://linux.vbird.org/linux_enterprise/0120installation.php)

[Red Hat: Installing Red Hat Enterprise Linux 7.4 on all architectures](https://access.redhat.com/documentation/zh-tw/red_hat_enterprise_linux/7/html/installation_guide/)
