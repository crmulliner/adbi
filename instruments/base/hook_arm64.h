/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

void (*log_function)(char *logmsg);

#define log(...) \
        {char __msg[1024] = {0};\
        snprintf(__msg, sizeof(__msg)-1, __VA_ARGS__);\
        log_function(__msg); }

struct hook_t_64 {
	unsigned int jump[13];
	unsigned int store[13];
	unsigned long int orig;
	unsigned long int patch;
	unsigned char name[128];
	void *data;
};

int start_coms(int *coms, char *ptsn);

void hook_cacheflush_64(unsigned long int begin, unsigned long int end);
int hook_64(struct hook_t_64 *h, int pid, char *libname, char *funcname, void *hook_arm);
void hook_precall_64(struct hook_t_64 *h);
void hook_postcall_64(struct hook_t_64 *h);
void unhook_64(struct hook_t_64 *h);
