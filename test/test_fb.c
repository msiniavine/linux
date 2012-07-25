#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "test.h"
#include <linux/fb.h>

#define USE_LIBC

#define FILENAME "/dev/fb0"

typedef unsigned char Byte;

int main ( void )
{
	//
	int Return = 0;
	
	int FBFD = 0;
	
	Byte *FBM = NULL;
	
	int Status = 0;
	struct fb_var_screeninfo VSI;
	struct fb_fix_screeninfo FSI;
	
	int Index = 0;
	struct fb_var_screeninfo VSI2;
	//
	
	//
	FBFD = open( FILENAME, O_RDWR );
	if ( FBFD == -1 )
	{
		perror( "open() \'" FILENAME "\'" );
		
		Return = 1;
		
		goto RETURN;
	}
	//
	
	//
	Status = ioctl( FBFD, FBIOGET_VSCREENINFO, &VSI );
	if ( Status == -1 )
	{
		perror( "ioctl() \'FBIOGET_VSCREENINFO\'" );
		
		Return = 1;
		
		goto RETURN;
	}
	
	Status = ioctl( FBFD, FBIOGET_FSCREENINFO, &FSI );
	if ( Status == -1 )
	{
		perror( "ioctl() \'FBIOGET_FSCREENINFO\'" );
		
		Return = 1;
		
		goto RETURN;
	}
	//
	
	//
	FBM = mmap( NULL, FSI.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, FBFD, 0 );
	if ( FBM == MAP_FAILED )
	{
		char Message[256] = "";
		
		sprintf( Message, "mmap() \'%d\' \'%d bytes\'", FBFD, FSI.smem_len );
	
		perror( Message );
		
		Return = 1;
		
		goto RETURN;
	}
	//
	
	enable_save_state();
	
	Index = 0;
	while ( 1 )
	{
		Status = ioctl( FBFD, FBIOGET_VSCREENINFO, &VSI2 );
		if ( Status == -1 )
		{
			perror( "ioctl() \'FBIOGET_VSCREENINFO\'" );
			
			Return = 2;
		
			break;
		}
		
		if ( VSI.bits_per_pixel == 8 )
		{
			( ( unsigned char * ) FBM )[Index] = 0xFF;
		}
		
		else if ( VSI.bits_per_pixel == 16 )
		{
			( ( unsigned short * ) FBM )[Index] = 0xFFFF;
		}
		
		else if ( VSI.bits_per_pixel == 24 )
		{
			( ( unsigned char * ) FBM )[Index] = 0xFF;	// B
			( ( unsigned char * ) FBM )[Index + 1] = 0xFF;	// G
			( ( unsigned char * ) FBM )[Index + 2] = 0xFF;	// R
		}
		
		else if ( VSI.bits_per_pixel == 32 )
		{
			( ( unsigned long * ) FBM )[Index] = 0xFFFFFFFF;
		}
		
		Index++;
		Index %= ( VSI.yres_virtual / 2 ) * ( FSI.line_length / ( VSI.bits_per_pixel / 8 ) );
	}
	
	munmap( FBM, FSI.smem_len );
	close( FBFD );

RETURN:
	return Return;
}

