#!/bin/bash

# Check VM Running
virsh list | grep ansible-deploy-pxe-test

if [ "$?" -eq 0 ]
then
  virsh shutdown ansible-deploy-pxe-test
	sleep 10

  rm -f /var/lib/libvirt/images/test.ovl
	qemu-img create -b /var/lib/libvirt/images/centos7.qcow2 -f qcow2 /var/lib/libvirt/images/pxe.ovl

	virsh start ansible-deploy-pxe-test
	sleep 15
	ssh root@192.168.1.2 "mkdir -p /mnt/pxe ; mount /dev/vdb1 /mnt/pxe ; echo nameserver 8.8.8.8 >> /etc/resolv.conf"

  ansible-playbook -i inventory setup.yml
  ssh root@192.168.1.2 "mount /mnt/pxe/CentOS-7-x86_64-DVD-1708.iso /var/www/html/centos74/"

else
  rm -f /var/lib/libvirt/images/test.ovl
	qemu-img create -b /var/lib/libvirt/images/centos7.qcow2 -f qcow2 /var/lib/libvirt/images/pxe.ovl

	virsh start ansible-deploy-pxe-test
  sleep 15
	ssh root@192.168.1.2 "mkdir -p /mnt/pxe ; mount /dev/vdb1 /mnt/pxe ; echo nameserver 8.8.8.8 >> /etc/resolv.conf"

  ansible-playbook -i inventory setup.yml
  ssh root@192.168.1.2 "mount /mnt/pxe/CentOS-7-x86_64-DVD-1708.iso /var/www/html/centos74/"
fi
