#include "test.h"


int strlen(char* string)
{
	int len = 0;
	for(;string[len] != '\0'; len++);
	return len;
}

int print(char* text)
{
	return write(1, text, strlen(text));
}

/* reverse:  reverse string s in place */
void reverse(char* s)
{
	int c, i, j;

	for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void itoa(int n, char s[])
{
	int i, sign;

	if ((sign = n) < 0)  /* record sign */
		n = -n;          /* make n positive */
	i = 0;
	do {       /* generate digits in reverse order */
		s[i++] = n % 10 + '0';   /* get next digit */
	} while ((n /= 10) > 0);     /* delete it */
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s);
} 



int print_int(int number)
{
	char buffer[256];
	itoa(number, buffer);
	return print(buffer);
}

void memset(void* start, int val, unsigned int size)
{
	char* buff = (char*)start;
	unsigned int i;
	for(i=0; i<size; i++)
	{
		buff[i] = (char)val;
	}
}


unsigned int check_mem(void* start, int expected, unsigned int size)
{
	char* buff = (char*)start;
	unsigned int i;
	for(i=0; i<size; i++)
	{
		if(buff[i] != expected) return i;
	}

	return 0;
}

void memory_copy(void* dst, void* src, unsigned int size)
{
	unsigned int i;
	char* dest = (char*)dst;
	char* source = (char*)src;
	for(i=0; i<size; i++)
	{
		dest[i] = source[i];
	}
}

