#include <unistd.h>
#include <stdio.h>

int main()
{
	unsigned long jiffies = syscall(338);
	printf("%lu %ld %lx\n", jiffies, jiffies, jiffies);
	return 0;
}
