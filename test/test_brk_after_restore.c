#include "test.h"

int _start()
{
        unsigned int start, end, err;
        start = brk(0);
//      print_int(cur_brk); print("\n");                                                                                                                     
        end = start + 0x1000;
        err = brk(end);
        if(err != end) exit(1);

        memset((void*)start, 0x61, end - start);
        enable_save_state();
        while(!was_state_restored());
        if(check_mem((void*)start, 0x61, end-start)) exit(1);

	end += 0xa000;
	err = brk(end);
	if(err != end) exit(2);

	memset((void*)start, 0x62, end-start);
	if(!check_mem((void*)start, 0x62, end-start)) exit(0);
        exit(3);
}

