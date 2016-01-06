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

#include "../base/hook.h"
#include "../base/base.h"

#undef log

#define log(...)                                                               \
  {                                                                            \
    FILE *fp = fopen("/data/local/tmp/adbi_example.log", "a+");                \
    if (fp) {                                                                  \
      fprintf(fp, __VA_ARGS__);                                                \
      fclose(fp);                                                              \
    }                                                                          \
  }

// this file is going to be compiled into a thumb mode binary

void __attribute__((constructor)) my_init(void);

static struct hook_t eph;

// for demo code only
static int counter;

// arm version of hook
extern ssize_t my_recv_arm(int socket, void *buffer, size_t length, int flags);

/*
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg) { log("%s", msg) }

ssize_t my_recv(int socket, void *buffer, size_t length, int flags) {
  int (*orig_recv)(int socket, void *buffer, size_t length, int flags);
  orig_recv = (void *)eph.orig;
  hook_precall(&eph);
  ssize_t res = orig_recv(socket, buffer, length, flags);
  if (counter) {
    hook_postcall(&eph);
    log("recv() called\n");
    counter--;
    if (!counter)
      log("removing hook for recv()\n");
  }
  return res;
}

void my_init(void) {
  counter = 3;

  log("%s started\n", __FILE__) set_logfunction(my_log);

  hook(&eph, getpid(), "libc.", "recv", my_recv_arm, my_recv);
}
