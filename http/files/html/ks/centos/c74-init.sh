#!/bin/bash

wget https://my-netdata.io/kickstart-static64.sh
bash kickstart-static64.sh

# set yum proxy
#echo "proxy=http://10.2.11.167:3128" >> /etc/yum.conf

# install epel repo
yum install -y epel-release

# os update
yum update -y
yum upgrade -y

# install pkgs
yum install -y ansible htop ncdu bmon smem iftop telegraf screen zlib-devel perl-devel asciidoc xmlto docbook2X make tcl build-essential tk gettext perl-devel perl-CPAN
yum clean all

systemctl disable telegraf

# docbook soft link
#ln -s /usr/bin/db2x_docbook2texi /usr/bin/docbook2x-texi

# download git source code
#wget -P /usr/local/src/ https://www.kernel.org/pub/software/scm/git/git-2.15.1.tar.gz
#tar zxvf /usr/local/src/git-2.15.1.tar.gz -C /usr/local/src/

# build git source code
#cd /usr/local/src/git-2.15.1
#./configure
#make all doc info
#make install install-doc install-html install-info

# git-completion
#cp -a /usr/local/src/git-2.15.1/contrib/completion/git-completion.bash /etc/profile.d/
#echo "source /etc/profile.d/git-completion.bash" >> /etc/profile

# del file
#rm -rf /usr/local/src/git-2.15.1.tar.gz
#rm -rf /usr/local/src/git-2.15.1
rm -f /root/*.cfg
rm -f /root/*.log
