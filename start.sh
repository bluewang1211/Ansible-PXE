#!/bin/bash

# Check Ansible
rpm -qa | grep ansible -q

if [ "$?" -eq 0 ]
then
  echo "ansible is already installed."
else
  yum install -y ansible
fi

# Run PlayBook
ansible-playbook -i inventory setup.yml

