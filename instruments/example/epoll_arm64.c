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
#include <stdlib.h>

#include "../base/hook_arm64.h"
#include "../base/base.h"

#undef log

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/adbi_example.log", "a+"); if (fp) {\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}}


// this file is going to be compiled into a thumb mode binary

void __attribute__ ((constructor)) my_init(void);

static struct hook_t_64 eph_64;

/*
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg)
}
jstring my_hello(JNIEnv* env, jobject obj)
{
  log("hooked hello called!\n");
  jstring (*original_func)(JNIEnv* env, jobject obj);
  original_func = (void*)eph_64.orig;

  hook_precall_64(&eph_64);
  jstring res = original_func(env, obj);
	hook_postcall_64(&eph_64);

	return res;
}

void my_init(void)
{
	log("%s started\n", __FILE__)

	set_logfunction(my_log);

	hook_64(&eph_64, getpid(), "libnative-lib.", "Java_com_zvin_testndk_MainActivity_hello", my_hello);
}
