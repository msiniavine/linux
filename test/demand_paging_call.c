#include <stdio.h>

// calculatest nth fibonacci number
int make_demand_paging_call(int n)
{
	int a = 0;
	int b = 1;
	int c;
	int i;
	for(i = 0; i<n; i++)
	{
		c=a+b;
		a=b;
		b=c;
	}

	return c;
}


int main()
{
	printf("%d\n", make_demand_paging_call(10));
	return 0;
}

