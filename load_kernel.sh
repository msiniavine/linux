#!/bin/bash

for i in {1..100}
do
    /bin/true
done

cd test
{
    sleep 10
    kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 maxcpus=4 reset_devices load_state"
    ./save_state
} &

#sudo -u maxim /home/maxim/apache/bin/apachectl start
#./launcher `pidof httpd | awk '{ print $NF }'`

#./launcher `pidof memcached`

#./launcher `pidof mysqld`

#./test_runner

Xfbdev -dumb -softCursor -retro &
sleep 3
./launcher `pidof Xfbdev`


#kexec -l /boot/vmlinuz-`uname -r` --initrd=/boot/initrd.img-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk bootmem_debug"
#kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk"
#kexec -e
