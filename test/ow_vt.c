#include <linux/kernel.h>
#include <linux/kd.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>
#define __IN_KERNEL__
#include <otherworld/otherworld.h>


long get_video_data(struct task_struct* ts,ow_vt_data* vtd,unsigned short** screen_buffer, struct termios* termios)
{
	struct signal_struct signal;
	struct tty_struct tty;
	struct vc_data vcd;
	struct tty_driver driver;
	
	unsigned long p;
	int read=0;


	memchr(&signal,0,sizeof(signal));
	memchr(&tty,0,sizeof(tty));
	memchr(&vcd,0,sizeof(vcd));

	if (!ts || !vtd)
		return -EFAULT;
// Get task signal structure
	p=(unsigned long)ts->signal;
	read=ow_read_oldmem((char*)&signal,sizeof(signal),&p);
	if (read!=sizeof(signal))
		return -EFAULT;

// Get task TTY
	p=(unsigned long)signal.tty;
	if (!p)
		return -ENOTTY;
	read=ow_read_oldmem((char*)&tty,sizeof(tty),&p);
	if (read!=sizeof(tty))
		return -EFAULT;

// Check that this is virtual console driver
	p=(unsigned long)tty.driver;
	if (!p)
		return -ENOTTY;
	read=ow_read_oldmem((char*)&driver,sizeof(driver),&p);
	if (read!=sizeof(driver))
		return -ENOTTY;
	if (driver.type!=TTY_DRIVER_TYPE_CONSOLE || driver.subtype!=0)
		return -ENOTTY;
	
// Getting driver data - now we sure that it should be of type vc_data
	p=(unsigned long)tty.driver_data;
	if (!p)
		return -ENOENT;
	read=ow_read_oldmem((char*)&vcd,sizeof(vcd),&p);
	if (read!=sizeof(vcd))
		return -EFAULT;
	vtd->index=vcd.vc_num;
	vtd->rows=vcd.vc_rows;
	vtd->columns=vcd.vc_cols;
	vtd->screen_buffer_size=vcd.vc_screenbuf_size;
// Getting screen buffer
	if (screen_buffer!=NULL)
		*screen_buffer=kmalloc(vcd.vc_screenbuf_size,GFP_KERNEL);
	if (!(*screen_buffer))
		return -ENOMEM;
	p=(unsigned long)vcd.vc_screenbuf;
	read=ow_read_oldmem((char*)(*screen_buffer),vtd->screen_buffer_size,&p);
	if (read!=vtd->screen_buffer_size)
		return -EFAULT;

	// Getting termios flags
	if (tty.termios!=NULL && termios)
	{
		p=(unsigned long)tty.termios;
		if (!p)
			return -ENOTTY;
		read=ow_read_oldmem((char*)termios,sizeof(struct termios),&p);
		if (read!=sizeof(struct termios))
			return -ENOTTY;
	}

	return 0;
}

long ow_copy_console(struct tty_struct* tty, struct task_struct* ow_task)
{
	ow_vt_data ow_vtd;
	unsigned short* screen_buffer=NULL;
	struct vc_data* vcd=(struct vc_data*)(tty->driver_data);
	long result=0;
	struct termios termios;

	if (tty->driver->type != TTY_DRIVER_TYPE_CONSOLE || tty->driver->subtype!=0)
		return -ENOENT;
	
	if ((result=get_video_data(ow_task,&ow_vtd,&screen_buffer,&termios))<0)
		return result;
	if (ow_vtd.rows!=vcd->vc_rows || ow_vtd.columns!=vcd->vc_cols)
	{
		result=-EINVAL;
		goto exit;
	}
	memcpy(vcd->vc_screenbuf,screen_buffer,ow_vtd.screen_buffer_size);
	redraw_screen(vcd,0);
	change_termios(tty,&termios);
	redraw_screen(vcd,0);
exit:
	if (screen_buffer)
		kfree(screen_buffer);
	return result;
}