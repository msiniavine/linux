#ifndef MOUSEDEV_H
#define MOUSEDEV_H

#include <linux/input.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock_types.h>
#include <linux/device.h>
#include <linux/fs.h>

#define MOUSEDEV_MINOR_BASE	32
#define MOUSEDEV_MINORS		32
#define MOUSEDEV_MIX		31

struct mousedev_hw_data
{
	int dx, dy, dz;
	int x, y;
	int abs_event;
	unsigned long buttons;
};

struct mousedev
{
	int exist;
	int open;
	int minor;
	struct input_handle handle;
	wait_queue_head_t wait;
	struct list_head client_list;
	spinlock_t client_lock; /* protects client_list */
	struct mutex mutex;
	struct device dev;

	struct list_head mixdev_node;
	int mixdev_open;

	struct mousedev_hw_data packet;
	unsigned int pkt_count;
	int old_x[4], old_y[4];
	int frac_dx, frac_dy;
	unsigned long touch;
};

enum mousedev_emul
{
	MOUSEDEV_EMUL_PS2,
	MOUSEDEV_EMUL_IMPS,
	MOUSEDEV_EMUL_EXPS
};

struct mousedev_motion
{
	int dx, dy, dz;
	unsigned long buttons;
};

#define PACKET_QUEUE_LEN	16
struct mousedev_client
{
	struct fasync_struct *fasync;
	struct mousedev *mousedev;
	struct list_head node;

	struct mousedev_motion packets[PACKET_QUEUE_LEN];
	unsigned int head, tail;
	spinlock_t packet_lock;
	int pos_x, pos_y;

	signed char ps2[6];
	unsigned char ready, buffer, bufsiz;
	unsigned char imexseq, impsseq;
	enum mousedev_emul mode;
	unsigned long last_buttons;
};

#endif

