CFLAGS = -g -Wall -fno-stack-protector
#LDFLAGS = -lpthread


all: test_simple_fork test_stack test_sleep test_pid test_sighandler test_sighandler_call test_pending_signals test_restore_signal test_altstack test_sigsuspend test_loop run_test set_state test_parent_child save_state test_thread test_wait test_my_mutex test_condvar test_pipe1 test_pipe2 test_terminal launcher test_runner test_cli_full test_cli test_serv state_present test_sockserver test_sockload test_fork

syscalls.o: syscalls.S
	as syscalls.S -o syscalls.o

test_syscall.o: test_syscall.S

test.o: test.c

#test_file: file_test.o syscalls.o libc.o
#gcc -nostdlib -g syscalls.o file_test.o libc.o -o test_file

#test_demand_paging: test_demand_paging.o demand_paging_call.o
#gcc -nostdlib -g syscalls.o test_demand_paging.o demand_paging_call.o -o test_demand_paging

#demand_paging_call.o: demand_paging_call.s
#as demand_paging_call.s -o demand_paging_call.o

test_stack: syscalls.o test_stack.o
	gcc -nostdlib -g test_stack.o syscalls.o -o test_stack

test_simple_fork: syscalls.o test_simple_fork.o
	gcc -nostdlib -g test_simple_fork.o syscalls.o -o test_simple_fork

test_pipe1: syscalls.o test_pipe1.o
	gcc -nostdlib -g test_pipe1.o syscalls.o -o test_pipe1
test_pipe2: test_pipe2.o test.o

#test_brk: test_brk.o
#gcc -nostdlib -g test_brk.o syscalls.o libc.o -o test_brk

#test_brk_after_restore: test_brk_after_restore.o
#gcc -nostdlib -g test_brk_after_restore.o syscalls.o libc.o -o test_brk_after_restore

test_sleep: test_sleep.o test.o

#test_sysenter_vdso: test_sysenter_vdso.o syscalls.o
#gcc -g -nostdlib test_sysenter_vdso.o syscalls.o -o test_sysenter_vdso

#test_sysenter: test_sysenter.o syscalls.o
#gcc -nostdlib -g test_sysenter.o syscalls.o -o test_sysenter

#test_elfaux: test_elfaux.o syscalls.o libc.o
#gcc -nostdlib -g test_elfaux.o syscalls.o libc.o -o test_elfaux

state_present: state_present.o test.o
test_runner: test_runner.o test.o
test_pid: test_pid.o test.o
save_state: save_state.o test.o
test_parent_child: test_parent_child.o test_syscall.o test.o
test_sighandler: test_sighandler.o test.o
test_sighandler_call: test_sighandler_call.o test.o
test_pending_signals: test_pending_signals.o test.o
test_restore_signal: test_restore_signal.o test.o
test_altstack: test_altstack.o test.o
test_sigsuspend: test_sigsuspend.o test.o
test_loop: test_loop.o syscalls.o
	gcc -nostdlib -g test_loop.o syscalls.o -o test_loop
run_test: run_test.o
set_state: set_state.o
	gcc -nostdlib -g -o set_state set_state.o
test_thread: test_thread.o test.o
	gcc -g -o test_thread test_thread.o test.o -pthread
test_wait: test_wait.o test.o

test_my_mutex: test_my_mutex.o test.o
	gcc -g -o test_my_mutex test_my_mutex.o test.o -lpthread
test_condvar: test_condvar.o test.o
	gcc -g -o test_condvar test_condvar.o test.o -lpthread
test_terminal: test_terminal.o test.o
launcher: launcher.o test.o
test_cli_full: test_cli_full.o test.o
test_serv: test_serv.o test.o
test_cli: test_cli.o syscalls.o
	gcc -nostdlib -g test_cli.o syscalls.o -o test_cli
test_sockserver: test_sockserver.o test.o
test_sockload: test_sockload.o test.o
test_fork: test_fork.o test.o

#file_test.o: file_test.c
#gcc -c -nostdlibc file_test.c -o file_test.o


#ptrace: ptrace.o

clean:
	-rm *.o
	-rm test_fork
	-rm test_sockload
	-rm test_sockserver
	-rm state_present
	-rm test_cli
	-rm test_cli_full
	-rm test_serv
	-rm starter
	-rm test_runner
	-rm launcher
	-rm test_terminal
	-rm test_condvar
	-rm test_my_futex
	-rm test_wait
	-rm test_simple_fork
	-rm test_pipe1
	-rm test_pipe2
	-rm test_thread
	-rm test_stack
	-rm save_state
	-rm set_state
	-rm test_parent_child
	-rm test_loop
	-rm test_file
	-rm test_demand_paging
	-rm test_stack
	-rm test_brk
	-rm test_brk_after_restore
	-rm test_sleep
	-rm test_sysenter_vdso
	-rm test_sysenter
	-rm test_elfaux
	-rm ptrace
	-rm test_pid
	-rm test_sighandler
	-rm test_sighandler_call
	-rm test_pending_signals
	-rm test_restore_signal
	-rm test_altstack
	-rm test_sigsuspend
	-rm run_test
	-rm *~
