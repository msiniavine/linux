#!/bin/bash

cd test
{
    sleep 10
    kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state kgdboc=ttyS0,115200 kgdbwait"
    kexec -e
} &

#./test_sockerver &

./test_sockload -h 192.168.122.1 -p 5000 -t
#./test_tempfile

#echo "All test started, rebooting kernel"
#sleep 1

#kexec -l /boot/vmlinuz-`uname -r` --initrd=/boot/initrd.img-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk bootmem_debug"
#kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state kgdboc=ttyS0,115200 kgdbwait"
#kexec -e
