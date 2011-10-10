#!/bin/bash

cd test
{
    sleep 10
    kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state"
    kexec -e
} &

#sudo -u maxim /home/maxim/apache/bin/apachectl start
#./launcher `pidof httpd | awk '{ print $NF }'`

#./launcher `pidof mysqld`

./test_sockload -h 192.168.122.1 -p 5000 -t

#kexec -l /boot/vmlinuz-`uname -r` --initrd=/boot/initrd.img-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk bootmem_debug"
#kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk"
#kexec -e
