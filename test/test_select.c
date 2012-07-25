#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "test.h"

#define USE_LIBC

#define FD_STDIN 0

int main ( void )
{
	//
	fd_set ReadSet;
	
	int Status = 0;
	//
	
	//
	FD_ZERO( &ReadSet );
	FD_SET( FD_STDIN, &ReadSet );
	//

	enable_save_state();
	
	//
	Status = select( FD_STDIN + 1, &ReadSet, NULL, NULL, NULL );
	if ( Status >= 0 )
	{
		printf( "select() returned %d\n", Status );
		printf( "\n" );
		printf( "Read\n" );
		printf( "\tFD %d -> %d\n", FD_STDIN, FD_ISSET( FD_STDIN, &ReadSet ) );
	}
	else
	{
		perror( "select()" );
		
		return 1;
	}
	//

	return 0;
}

