#define NO_LIBC
#include "test.h"

int _start()
{
  enable_save_state();
  while(1);
  return 0;
}

