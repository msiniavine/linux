#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>
#include <fcntl.h>
#include "test.h"

#define USE_LIBC

#define MASTER "/dev/ptmx"

int main ( void )
{
	//
	int Status = 0;
	int PMFD = 0;
	int PSFD = 0;
	char SlavePath[PATH_MAX] = "";
	//

	//
	PMFD = open( MASTER, O_RDWR );
	if ( PMFD == -1 )
	{
		perror( "open() \'" MASTER "\'" );
		
		return 1;
	}
	//
	
	//
	Status = grantpt( PMFD );
	if ( Status == -1 )
	{
		char Message[256] = "";
		sprintf( Message, "grantpt() %d", PMFD );
		
		perror( Message );
		
		return 1;
	}
	
	Status = unlockpt( PMFD );
	if ( Status == -1 )
	{
		char Message[256] = "";
		sprintf( Message, "unlockpt() \'%d\'", PMFD );
		
		perror( Message );
		
		return 1;
	}
	//
	
	//
	strcpy( SlavePath, ptsname( PMFD ) );
	PSFD = open( SlavePath, O_RDWR );
	if ( PSFD == -1 )
	{
		char Message[256] = "";
		sprintf( Message, "open() \'%s\'", SlavePath );
	
		perror( Message );
		
		return 1;
	}
	
	/*PSFD = open( "/dev/pts/0", O_RDWR );
	if ( PSFD == -1 )
	{
		perror( "open() \'/dev/pts/0\'" );
		
		return 1;
	}*/
	//
	
	enable_save_state();
	
	while ( 1 )
	{
	}

	return 0;
}

