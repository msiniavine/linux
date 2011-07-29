#!/bin/bash

cd test
{
    sleep 5
    kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda8 ro"
    kexec -e
} &

#./test_loop < test_pid.c &> test.out
#./test_sockload -h 142.150.234.186 -p 5000 -l 4 < test_pid.c &> test.out
#./test_sockserver
#./test_sleep < test_pid.c &> test.out

#./script &
#./script2 &

#cd test
#./test_loop
#./test_fb < test_pid.c &> test.out &
#./test_fb < test_pid.c &> test.out &
#./test_fb < test_pid.c &> test.out &
#./test_fb < test_pid.c &> test.out &
#./test_fb < test_pid.c &> test.out &
#./test_fb &
#./test_fb &
#./test_fb &
#./test_fb &
#./test_fb &
#./test_fb
#./test_fb < test_pid.c &> test.out
#./test_pseudo
#./test_select

#echo "All test started, rebooting kernel"
#sleep 1

#kexec -l /boot/vmlinuz-`uname -r` --initrd=/boot/initrd.img-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk bootmem_debug"
#kexec -l /boot/vmlinuz-`uname -r` --append="root=/dev/sda1 1 irqpoll maxcpus=4 reset_devices load_state debug early_printk"
#kexec -e
