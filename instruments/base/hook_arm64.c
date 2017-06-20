/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>

#include "util.h"
#include "hook_arm64.h"

//void __attribute__ ((constructor)) my_init(void);

int hook_64(struct hook_t_64 *h, int pid, char *libname, char *funcname, void *hook_arm)
{
	unsigned long int addr;
	int i;

	if (find_name(pid, funcname, libname, &addr) < 0) {
		log("can't find: %s\n", funcname)
		return 0;
	}

	log("hooking:   %s = 0x%lx ", funcname, addr)
	strncpy(h->name, funcname, sizeof(h->name)-1);

	if (addr % 4 == 0) {
		log("ARM using 0x%lx\n", (unsigned long)hook_arm)
		h->patch = (unsigned long int)hook_arm;
		h->orig = addr;
		h->jump[0] = 0xd10083ff; // 				sub     sp, sp, #0x20
		h->jump[1] = 0xa9017bfd; // 				stp     x29, x30, [sp, #0x10]
		h->jump[2] = 0xa90023e7; //					stp     x7, x8, [sp]
		h->jump[3] = 0x94000001; //					bl      label1
		h->jump[4] = 0xaa1e03e7; // label1:	mov     x7, x30
		h->jump[5] = 0xf841c0e8; // 				ldr     x8, [x7, #28]
		h->jump[6] = 0xd63f0100; //					blr     x8
		h->jump[7] = 0xa94023e7; //					ldp     x7, x8, [sp]
		h->jump[8] = 0xa9417bfd; // 				ldp     x29, x30, [sp, #0x10]
		h->jump[9] = 0x910083ff; // 				add     sp, sp, #0x20
		h->jump[10] = 0xd65f03c0; //				ret
		h->jump[11] = h->patch & 0xffffffff; //store patch address
		h->jump[12] = (h->patch >> 32) & 0xffffffff;
		for (i = 0; i < 13; i++)
			h->store[i] = ((int*)h->orig)[i];
		for (i = 0; i < 13; i++)
			((int*)h->orig)[i] = h->jump[i];
	}
	hook_cacheflush_64((unsigned long int)h->orig, (unsigned long int)h->orig+sizeof(h->jump));
	return 1;
}

void inline hook_cacheflush_64(unsigned long int begin, unsigned long int end)
{
	printf("hook_cacheflush called!");
	__builtin___clear_cache((char*)begin, (char*)end);
}

void hook_precall_64(struct hook_t_64 *h)
{
	int i;

	for (i = 0; i < 13; i++)
		((int*)h->orig)[i] = h->store[i];

	hook_cacheflush_64((unsigned long int)h->orig, (unsigned long int)h->orig+sizeof(h->jump));
}

void hook_postcall_64(struct hook_t_64 *h)
{
	int i;

	for (i = 0; i < 13; i++)
		((int*)h->orig)[i] = h->jump[i];

	hook_cacheflush_64((unsigned long int)h->orig, (unsigned long int)h->orig+sizeof(h->jump));
}

void unhook_64(struct hook_t_64 *h)
{
	log("unhooking %s = %lx  hook = %lx \n", h->name, h->orig, h->patch)
	hook_precall_64(h);
}

/*
 *  workaround for blocked socket API when process does not have network
 *  permissions
 *
 *  this code simply opens a pseudo terminal (pty) which gives us a
 *  file descriptor. the pty then can be used by another process to
 *  communicate with our instrumentation code. an example program
 *  would be a simple socket-to-pty-bridge
 *
 *  this function just creates and configures the pty
 *  communication (read, write, poll/select) has to be implemented by hand
 *
 */
int start_coms(int *coms, char *ptsn)
{
	if (!coms) {
		log("coms == null!\n")
		return 0;
	}

	*coms = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	if (*coms <= 0) {
		log("posix_openpt failed\n")
		return 0;
	}
	//else
	//	log("pty created\n")
	if (unlockpt(*coms) < 0) {
		log("unlockpt failed\n")
		return 0;
	}

	if (ptsn)
		strcpy(ptsn, (char*)ptsname(*coms));

	struct termios  ios;
	tcgetattr(*coms, &ios);
	ios.c_lflag = 0;  // disable ECHO, ICANON, etc...
	tcsetattr(*coms, TCSANOW, &ios);

	return 1;
}
