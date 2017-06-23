/*
 * hijack.c - force a process to load a library
 *
 *  ARM / Android version by:
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *	(c) 2012,2013
 *
 *
 *  original x86 version by:
 *  Copyright (C) 2002 Victor Zandy <zandy[at]cs.wisc.edu>
 *
 *  License: LGPL 2.1
 *
 *
 *
 *	arm64-v8a version by:
 *	vincent chen
 *	chenzwkeepmoving@gmail.com
 */

#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>

int debug = 0;
int zygote = 0;
int nomprotect = 0;
// unsigned int stack_start;   //32bit
// unsigned int stack_end;

unsigned long int stack_start;   //64bit
unsigned long int stack_end;

/* memory map for libraries */
#define MAX_NAME_LEN 256
#define MEMORY_ONLY  "[memory]"
struct mm {
	char name[MAX_NAME_LEN];
	unsigned long start, end;
};

typedef struct symtab *symtab_t;
struct symlist {
	Elf64_Sym *sym;       /* symbols */
	char *str;            /* symbol strings */
	unsigned num;         /* number of symbols */
};
struct symtab {
	struct symlist *st;    /* "static" symbols */
	struct symlist *dyn;   /* dynamic symbols */
};

static void *
xmalloc(size_t size)
{
	void *p;
	p = malloc(size);
	if (!p) {
		printf("Out of memory\n");
		exit(1);
	}
	return p;
}

static struct symlist *
get_syms(int fd, Elf64_Shdr *symh, Elf64_Shdr *strh)
{
	struct symlist *sl, *ret;
	int rv;

	ret = NULL;
	sl = (struct symlist *) xmalloc(sizeof(struct symlist));
	sl->str = NULL;
	sl->sym = NULL;

	/* sanity */
	if (symh->sh_size % sizeof(Elf64_Sym)) {
		printf("elf_error\n");
		goto out;
	}

	/* symbol table */
	sl->num = symh->sh_size / sizeof(Elf64_Sym);
	sl->sym = (Elf64_Sym *) xmalloc(symh->sh_size);
	rv = pread(fd, sl->sym, symh->sh_size, symh->sh_offset);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != symh->sh_size) {
		printf("elf error\n");
		goto out;
	}

	/* string table */
	sl->str = (char *) xmalloc(strh->sh_size);
	rv = pread(fd, sl->str, strh->sh_size, strh->sh_offset);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != strh->sh_size) {
		printf("elf error");
		goto out;
	}

	ret = sl;
out:
	return ret;
}

static int
do_load(int fd, symtab_t symtab)
{
	int rv;
	size_t size;
	Elf64_Ehdr ehdr;
	Elf64_Shdr *shdr = NULL, *p;
	Elf64_Shdr *dynsymh, *dynstrh;
	Elf64_Shdr *symh, *strh;
	char *shstrtab = NULL;
	int i;
	int ret = -1;

	/* elf header */
	rv = read(fd, &ehdr, sizeof(ehdr));
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != sizeof(ehdr)) {
		printf("elf error\n");
		goto out;
	}
	if (strncmp(ELFMAG, ehdr.e_ident, SELFMAG)) { /* sanity */
		printf("not an elf\n");
		goto out;
	}
	if (sizeof(Elf64_Shdr) != ehdr.e_shentsize) { /* sanity */
		printf("elf error\n");
		goto out;
	}

	/* section header table */
	size = ehdr.e_shentsize * ehdr.e_shnum;
	shdr = (Elf64_Shdr *) xmalloc(size);
	rv = pread(fd, shdr, size, ehdr.e_shoff);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error");
		goto out;
	}

	/* section header string table */
	size = shdr[ehdr.e_shstrndx].sh_size;
	shstrtab = (char *) xmalloc(size);
	rv = pread(fd, shstrtab, size, shdr[ehdr.e_shstrndx].sh_offset);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error\n");
		goto out;
	}

	/* symbol table headers */
	symh = dynsymh = NULL;
	strh = dynstrh = NULL;
	for (i = 0, p = shdr; i < ehdr.e_shnum; i++, p++)
		if (SHT_SYMTAB == p->sh_type) {
			if (symh) {
				printf("too many symbol tables\n");
				goto out;
			}
			symh = p;
		} else if (SHT_DYNSYM == p->sh_type) {
			if (dynsymh) {
				printf("too many symbol tables\n");
				goto out;
			}
			dynsymh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".strtab", 7)) {
			if (strh) {
				printf("too many string tables\n");
				goto out;
			}
			strh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".dynstr", 7)) {
			if (dynstrh) {
				printf("too many string tables\n");
				goto out;
			}
			dynstrh = p;
		}
	/* sanity checks */
	if ((!dynsymh && dynstrh) || (dynsymh && !dynstrh)) {
		printf("bad dynamic symbol table");
		goto out;
	}
	if ((!symh && strh) || (symh && !strh)) {
		printf("bad symbol table");
		goto out;
	}
	if (!dynsymh && !symh) {
		printf("no symbol table");
		goto out;
	}

	/* symbol tables */
	if (dynsymh)
		symtab->dyn = get_syms(fd, dynsymh, dynstrh);
	if (symh)
		symtab->st = get_syms(fd, symh, strh);
	ret = 0;
out:
	free(shstrtab);
	free(shdr);
	return ret;
}

static symtab_t
load_symtab(char *filename)
{
	int fd;
	symtab_t symtab;

	symtab = (symtab_t) xmalloc(sizeof(*symtab));
	memset(symtab, 0, sizeof(*symtab));

	fd = open(filename, O_RDONLY);
	if (0 > fd) {
		//perror("open");
		return NULL;
	}
	if (0 > do_load(fd, symtab)) {
		printf("Error ELF parsing %s\n", filename);
		free(symtab);
		symtab = NULL;
	}
	close(fd);
	return symtab;
}


static int
load_memmap(pid_t pid, struct mm *mm, int *nmmp)
{
	char raw[800000]; // this depends on the number of libraries an executable uses
	char name[MAX_NAME_LEN];
	char *p;
	unsigned long start, end;
	struct mm *m;
	int nmm = 0;
	int fd, rv;
	int i;

	sprintf(raw, "/proc/%d/maps", pid);
	fd = open(raw, O_RDONLY);
	if (0 > fd) {
		printf("Can't open %s for reading\n", raw);
		return -1;
	}

	/* Zero to ensure data is null terminated */
	memset(raw, 0, sizeof(raw));

	p = raw;
	while (1) {
		rv = read(fd, p, sizeof(raw)-(p-raw));
		if (0 > rv) {
			//perror("read");
			return -1;
		}
		if (0 == rv)
			break;
		p += rv;
		if (p-raw >= sizeof(raw)) {
			printf("Too many memory mapping\n");
			return -1;
		}
	}
	close(fd);

	p = strtok(raw, "\n");
	m = mm;
	while (p) {
		/* parse current map line */
		rv = sscanf(p, "%lx-%lx %*s %*s %*s %*s %s\n",
			    &start, &end, name);

		p = strtok(NULL, "\n");

		if (rv == 2) {
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, MEMORY_ONLY);
			continue;
		}

		if (strstr(name, "stack") != 0) {
			stack_start = start;
			stack_end = end;
		}

		/* search backward for other mapping with same name */
		for (i = nmm-1; i >= 0; i--) {
			m = &mm[i];
			if (!strcmp(m->name, name))
				break;
		}

		if (i >= 0) {
			if (start < m->start)
				m->start = start;
			if (end > m->end)
				m->end = end;
		} else {
			/* new entry */
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, name);
		}
	}

	*nmmp = nmm;
	return 0;
}

/* Find libc in MM, storing no more than LEN-1 chars of
   its name in NAME and set START to its starting
   address.  If libc cannot be found return -1 and
   leave NAME and START untouched.  Otherwise return 0
   and null-terminated NAME. */
static int
find_libc(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("libc", p, 4))
			continue;
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
find_linker_mem(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		//printf("name = %s\n", m->name);
		//printf("start = %x\n", m->start);
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("linker", p, 6))
			continue;
		break; // <--- hack
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
lookup2(struct symlist *sl, unsigned char type,
	char *name, unsigned long *val)
{
	Elf64_Sym *p;
	int len;
	int i;

	len = strlen(name);
	for (i = 0, p = sl->sym; i < sl->num; i++, p++) {
		//printf("name: %s %x\n", sl->str+p->st_name, p->st_value);
		if (!strncmp(sl->str+p->st_name, name, len)
		    && ELF64_ST_TYPE(p->st_info) == type) {
			//if (p->st_value != 0) {
			*val = p->st_value;
			return 0;
			//}
		}
	}
	return -1;
}

static int
lookup_sym(symtab_t s, unsigned char type,
	   char *name, unsigned long *val)
{
	if (s->dyn && !lookup2(s->dyn, type, name, val))
		return 0;
	if (s->st && !lookup2(s->st, type, name, val))
		return 0;
	return -1;
}

static int
lookup_func_sym(symtab_t s, char *name, unsigned long *val)
{
	return lookup_sym(s, STT_FUNC, name, val);
}

static int
find_name(pid_t pid, char *name, unsigned long *addr)
{
	struct mm mm[1000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (0 > load_memmap(pid, mm, &nmm)) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (0 > find_libc(libc, sizeof(libc), &libcaddr, mm, nmm)) {
		printf("cannot find libc\n");
		return -1;
	}
	s = load_symtab(libc);
	if (!s) {
		printf("cannot read symbol table\n");
		return -1;
	}
	if (0 > lookup_func_sym(s, name, addr)) {
		printf("cannot find %s\n", name);
		return -1;
	}
	*addr += libcaddr;
	return 0;
}

static int find_linker(pid_t pid, unsigned long *addr)
{
	struct mm mm[1000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (0 > load_memmap(pid, mm, &nmm)) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (0 > find_linker_mem(libc, sizeof(libc), &libcaddr, mm, nmm)) {
		printf("cannot find libc\n");
		return -1;
	}

	*addr = libcaddr;

	return 1;
}

/* Write NLONG 4 byte words from BUF into PID starting
   at address POS.  Calling process must be attached to PID. */
static int
write_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		// if (0 > ptrace(PTRACE_POKETEXT, pid, (void *)(pos+(i*4)), (void *)*p)) //32bit
		if (0 > ptrace(PTRACE_POKETEXT, pid, (void *)(pos+(i*8)), (void *)*p))  //64bit
			return -1;
	return 0;
}

static int
read_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++){
		// if ((*p = ptrace(PTRACE_PEEKTEXT, pid, (void *)(pos+(i*4)), (void *)*p)) < 0)
		if ((*p = ptrace(PTRACE_PEEKTEXT, pid, (void *)(pos+(i*8)), (void *)*p)) < 0){
			return -1;
		}

		printf("read_mem 0x%lx---> %lx\n", (pos+(i*8)), *p);
	}
	return 0;
}

unsigned int sc_old[] = {
// libname
0xe59f0030, // ldr     r0, [pc, #48] | addr of "libname" in r0
0xe3a01000, // mov     r1, #0        | r1 = 0 (flags=0)
0xe1a0e00f, // mov     lr, pc        | populate lr
0xe59ff028, // ldr     pc, [pc, #40] | call dlopen()
0xe59fd01c, // ldr     sp, [pc, #28] | fix sp
0xe59f0008, // ldr     r0, [pc, #12] | fix r0
0xe59f1008, // ldr     r1, [pc, #12] | fix r1
0xe59fe008, // ldr     lr, [pc, #12] | fix lr
0xe59ff008, // ldr     pc, [pc, #12] | fix pc (continue process)
0xe1a00000, // nop (mov r0,r0)       | r0
0xe1a00000, // nop (mov r0,r0)       | r1
0xe1a00000, // nop (mov r0,r0)       | lr
0xe1a00000, // nop (mov r0,r0)       | pc
0xe1a00000, // nop (mov r0,r0)       | sp
0xe1a00000, // nop (mov r0,r0)       | addr of libname
0xe1a00000  // nop (mov r0,r0)       | dlopen address
};

unsigned int sc[] = {
0xe59f0040, //        ldr     r0, [pc, #64]   ; 48 <.text+0x48>
0xe3a01000, //        mov     r1, #0  ; 0x0
0xe1a0e00f, //        mov     lr, pc
0xe59ff038, //        ldr     pc, [pc, #56]   ; 4c <.text+0x4c>
0xe59fd02c, //        ldr     sp, [pc, #44]   ; 44 <.text+0x44>
0xe59f0010, //        ldr     r0, [pc, #16]   ; 30 <.text+0x30>
0xe59f1010, //        ldr     r1, [pc, #16]   ; 34 <.text+0x34>
0xe59f2010, //        ldr     r2, [pc, #16]   ; 38 <.text+0x38>
0xe59f3010, //        ldr     r3, [pc, #16]   ; 3c <.text+0x3c>
0xe59fe010, //        ldr     lr, [pc, #16]   ; 40 <.text+0x40>
0xe59ff010, //        ldr     pc, [pc, #16]   ; 44 <.text+0x44>
0xe1a00000, //        nop                     r0
0xe1a00000, //        nop                     r1
0xe1a00000, //        nop                     r2
0xe1a00000, //        nop                     r3
0xe1a00000, //        nop                     lr
0xe1a00000, //        nop                     pc
0xe1a00000, //        nop                     sp
0xe1a00000, //        nop                     addr of libname
0xe1a00000, //        nop                     dlopenaddr
};

unsigned int sc_64[] = {
	0x94000001, //				bl      label1
	0xaa1e03e5,	//label1:	mov     x5, x30
	0xf84840a0,	//				ldr     x0, [x5, #132]
	0xd2800021,	//				mov     x1, #1
	0xf848c0a3,	//				ldr     x3, [x5, #140]
	0xd63f0060,	//				blr     x3
	0x94000001,	//				bl      label2
	0xaa1e03e5,	//label2:	mov     x5, x30
	0xf842c0a0,	//				ldr     x0, [x5, #44]
	0xf84340a1,	//				ldr     x1, [x5, #52]
	0xf843c0a3,	//				ldr     x3, [x5, #60]
	0xf844c0a4,	//				ldr     x4, [x5, #76]
	0x9100009f,	//				mov     sp, x4
	0xf84440a4,	//				ldr     x4, [x5, #68]
	0xf84540be,	//				ldr     x30, [x5, #84]
	0xf84640bc,	//				ldr     x28, [x5, #100]
	0xf845c0a5,	//				ldr     x5, [x5, #92]
	0xd65f0380,	//				ret     x28
	0x00000000,	//x0
	0x00000000,
	0x00000000,	//x1
	0x00000000,
	0x00000000,	//x3
	0x00000000,
	0x00000000, //x4
	0x00000000,
	0x00000000,	//sp
	0x00000000,
	0x00000000,	//x30(lr)
	0x00000000,
	0x00000000,	//x2
	0x00000000,
	0x00000000,	//pc
	0x00000000,
	0x00000000,	//addr of libname
	0x00000000,
	0x00000000,	//dlopen addr
	0x00000000,
	0x00000000,	//for stack alignment purpose
	0x00000000
};

struct pt_regs2 {
         long uregs[18];
};

//32bit
#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_ip          uregs[12]
#define ARM_fp          uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]

struct user_regs_struct_64 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

//64bit
#define ARM64_sp				sp
#define ARM64_pc 				pc
#define ARM64_pstate    pstate
#define ARM64_x0 				regs[0]
#define ARM64_x1 				regs[1]
#define ARM64_x2 				regs[2]
#define ARM64_x3 				regs[3]
#define ARM64_x4 				regs[4]
#define ARM64_lr 				regs[30]
#define ARM64_x8				regs[8]

// struct iovec {
//     ptr_t iov_base; /* Starting address */
//     size_t iov_len; /* Length in bytes */
// };

#define HELPSTR "error usage: %s -p PID -l LIBNAME [-d (debug on)] [-z (zygote)] [-m (no mprotect)] [-s (appname)] [-Z (trace count)] [-D (debug level)]\n"

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	struct pt_regs2 regs;
	unsigned long dlopenaddr, mprotectaddr, codeaddr, libaddr;
	unsigned long *p;
	int fd = 0;
	int n = 0;
	char buf[32];
	char *arg;
	int opt;
	char *appname = 0;

	struct user_regs_struct_64 regs_64;

	struct iovec iov = {
        .iov_base = &regs_64,
        .iov_len = sizeof(regs_64),
	};

 	while ((opt = getopt(argc, argv, "p:l:dzms:Z:D:")) != -1) {
		switch (opt) {
			case 'p':
				pid = strtol(optarg, NULL, 0);
				break;
			case 'Z':
				zygote = strtol(optarg, NULL, 0);
			break;
			case 'D':
				debug = strtol(optarg, NULL, 0);
			break;
			case 'l':
				n = strlen(optarg)+1;
				// n = n/4 + (n%4 ? 1 : 0); //32bit
				n = n/8 + (n%8 ? 1 : 0);   //64bit
				arg = malloc(n*sizeof(unsigned long));
				// memcpy(arg, optarg, n*4);  //32bit
				memcpy(arg, optarg, n*8);  //64bit
				break;
			case 'm':
				nomprotect = 1;
				break;
			case 'd':
				debug = 1;
				break;
			case 'z':
				zygote = 1;
				break;
			case 's':
				zygote = 1;
				appname = strdup(optarg);
				break;
			default:
				fprintf(stderr, HELPSTR, argv[0]);

				exit(0);
				break;
		}
	}

	if(debug){
		printf("main debug info ---> sizeof(int): %d, sizeof(long): %d, sizeof(unsigned long): %d, sizeof(long int): %d, sizeof(sc_64): %d\n", sizeof(int), sizeof(long), sizeof(unsigned long), sizeof(long int), sizeof(sc_64));
	}

	if(debug){
		printf("arg ---> %s\n", arg);
	}

	if (pid == 0 || n == 0) {
		fprintf(stderr, HELPSTR, argv[0]);
		exit(0);
	}

	if (!nomprotect) {
		if (0 > find_name(pid, "mprotect", &mprotectaddr)) {
			printf("can't find address of mprotect(), error!\n");
			exit(1);
		}
		if (debug)
			printf("mprotect: 0x%lx\n", mprotectaddr);
	}

	void *ldl = dlopen("libdl.so", RTLD_LAZY);
	if (ldl) {
		dlopenaddr = (unsigned long)dlsym(ldl, "dlopen");
		dlclose(ldl);
	}
	unsigned long int lkaddr;
	unsigned long int lkaddr2;
	find_linker(getpid(), &lkaddr);
	//printf("own linker: 0x%x\n", lkaddr);
	//printf("offset %x\n", dlopenaddr - lkaddr);
	find_linker(pid, &lkaddr2);
	//printf("tgt linker: %x\n", lkaddr2);
	//printf("tgt dlopen : %x\n", lkaddr2 + (dlopenaddr - lkaddr));

	if(debug){
		printf("dlopen relative addr: 0x%x \n", (dlopenaddr - lkaddr));
	}
	dlopenaddr = lkaddr2 + (dlopenaddr - lkaddr);

	if (debug)
		printf("dlopen: 0x%lx\n", dlopenaddr);

	// Attach
	if (0 > ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		printf("cannot attach to %d, error!\n", pid);
		exit(1);
	}
	waitpid(pid, NULL, 0);

	if (appname) {
		if (ptrace(PTRACE_SETOPTIONS, pid, (void*)1, (void*)(PTRACE_O_TRACEFORK))) {
			printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)");
			return -1;
		}
		ptrace(PTRACE_CONT, pid, (void*)1, 0);

		int t;
		int stat;
		int child_pid = 0;
		for (;;) {
			t = waitpid(-1, &stat, __WALL|WUNTRACED);

			if (t != 0 && t == child_pid) {
				if (debug > 1)
					printf(".");
				char fname[256];
				sprintf(fname, "/proc/%d/cmdline", child_pid);
				int fp = open(fname, O_RDONLY);
				if (fp < 0) {
					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
					continue;
				}
				read(fp, fname, sizeof(fname));
				close(fp);

				if (strcmp(fname, appname) == 0) {
					if (debug)
						printf("zygote -> %s\n", fname);

					// detach from zygote
					ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);

					// now perform on new process
					pid = child_pid;
					break;
				}
				else {
					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
					continue;
				}
			}

			if (WIFSTOPPED(stat) && (WSTOPSIG(stat) == SIGTRAP)) {
				if ((stat >> 16) & PTRACE_EVENT_FORK) {
					if (debug > 1)
						printf("fork\n");
					int b = t; // save parent pid
					ptrace(PTRACE_GETEVENTMSG, t, 0, &child_pid);
					if (debug)
						printf("PID=%d  child=%d\n", t, child_pid);
					t = child_pid;

					if (debug > 1)
						printf("continue parent (zygote) PID=%d\n", b);
					ptrace(PTRACE_CONT, b, (void*)1, 0);

					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
				}
			}
		}
	}

	if (zygote) {
		int i = 0;
		for (i = 0; i < zygote; i++) {
			// -- zygote fix ---
			// we have to wait until the syscall is completed, IMPORTANT!
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			if (debug > 1)
				printf("/");
			waitpid(pid, NULL, 0);

			ptrace(PTRACE_GETREGSET, pid, 0, &regs);
			if (regs.ARM_ip != 0) {
				if (debug > 1)
					printf("not a syscall entry, wait for entry\n");
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
				waitpid(pid, NULL, 0);
			}

			//if (debug)
			//	printf("process mode: currently waiting in SYSCALL\n");
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			if (debug > 1)
				printf("\\");
			waitpid(pid, NULL, 0);
			//if (debug)
			//	printf("process mode: SYSCALL completed now inject\n");
			// ---- need to work with zygote --- end ---
		}
	}
	if (debug > 1)
		printf("\n");

	sprintf(buf, "/proc/%d/mem", pid);
	fd = open(buf, O_WRONLY);
	if (0 > fd) {
		printf("cannot open %s, error!\n", buf);
		exit(1);
	}
	// ptrace(PTRACE_GETREGS, pid, 0, &regs);   //32bit
  if(0 > ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, (void*)&iov)){   //64bit
		printf("get registers failed!");
		exit(1);
	}

  if(debug){
    printf("PTRACE_GETREGSET ---> iov start: 0x%lx, iov length: %d\n", iov.iov_base, iov.iov_len);
  }

	// setup variables of the loading and fixup code
	/*
	sc[9] = regs.ARM_r0;
	sc[10] = regs.ARM_r1;
	sc[11] = regs.ARM_lr;
	sc[12] = regs.ARM_pc;
	sc[13] = regs.ARM_sp;
	sc[15] = dlopenaddr;
	*/

	//32bit
	// sc[11] = regs.ARM_r0;
	// sc[12] = regs.ARM_r1;
	// sc[13] = regs.ARM_r2;
	// sc[14] = regs.ARM_r3;
	// sc[15] = regs.ARM_lr;
	// sc[16] = regs.ARM_pc;
	// sc[17] = regs.ARM_sp;
	// sc[19] = dlopenaddr;

	//64bit
	sc_64[18] = regs_64.ARM64_x0 & 0xffffffff;
	sc_64[19] = (regs_64.ARM64_x0 >> 32) & 0xffffffff;
	sc_64[20] = regs_64.ARM64_x1 & 0xffffffff;
	sc_64[21] = (regs_64.ARM64_x1 >> 32) & 0xffffffff;
	sc_64[21] = regs_64.ARM64_x3 & 0xffffffff;
	sc_64[23] = (regs_64.ARM64_x3 >> 32) & 0xffffffff;
	sc_64[24] = regs_64.ARM64_x4 & 0xffffffff;
	sc_64[25] = (regs_64.ARM64_x4 >> 32) & 0xffffffff;
	sc_64[26] = regs_64.ARM64_sp & 0xffffffff;
	sc_64[27] = (regs_64.ARM64_sp >> 32) & 0xffffffff;
	sc_64[28] = regs_64.ARM64_lr & 0xffffffff;
	sc_64[29] = (regs_64.ARM64_lr >> 32) & 0xffffffff;
	sc_64[30] = regs_64.ARM64_x2 & 0xffffffff;
	sc_64[31] = (regs_64.ARM64_x2 >> 32) & 0xffffffff;
	sc_64[32] = regs_64.ARM64_pc & 0xffffffff;
	sc_64[33] = (regs_64.ARM64_pc >> 32) & 0xffffffff;
	sc_64[36] = dlopenaddr & 0xffffffff;
	sc_64[37] = (dlopenaddr >> 32) & 0xffffffff;

	if(debug){
		printf("set value completed!\n");
	}

	if (debug) {
		printf("pc=%lx lr=%lx sp=%lx \n", regs_64.ARM64_pc, regs_64.ARM64_lr, regs_64.ARM64_sp);
		printf("x0=%lx x1=%lx\n", regs_64.ARM64_x0, regs_64.ARM64_x1);
		printf("x2=%lx x3=%lx\n", regs_64.ARM64_x2, regs_64.ARM64_x3);
		printf("x4=%lx\n", regs_64.ARM64_x4);
	}

	// push library name to stack
	// libaddr = regs.ARM_sp - n*4 - sizeof(sc);  //32bit
	libaddr = regs_64.ARM64_sp - n*8 - sizeof(sc_64);  //64bit

	sc_64[34] = libaddr & 0xffffffff;
	sc_64[35] = (libaddr >> 32) & 0xffffffff;

	if(debug){
		printf("sc_64[34]=%x sc_64[35]=%x \n", sc_64[34], sc_64[35]);
	}

	// sc[18] = libaddr;
	//sc[14] = libaddr;
	//printf("libaddr: %x\n", libaddr);

	if (stack_start == 0) {
		stack_start = (unsigned long int) strtol(argv[3], NULL, 16);
		stack_start = stack_start << 12;
		stack_end = stack_start + strtol(argv[4], NULL, 0);
	}

	// write library name to stack
	if (0 > write_mem(pid, (unsigned long*)arg, n, libaddr)) {
		printf("cannot write library name (%s) to stack, error!\n", arg);
		exit(1);
	}

	// write code to stack
	// codeaddr = regs.ARM_sp - sizeof(sc); //32bit
	codeaddr = regs_64.ARM64_sp - sizeof(sc_64);  //64bit
	if (0 > write_mem(pid, (unsigned long*)&sc_64, sizeof(sc_64)/sizeof(long), codeaddr)) {
		printf("cannot write code, error!\n");
		exit(1);
	}

	unsigned long *my_buff;
	my_buff = (unsigned long*)malloc(n*8 + sizeof(sc_64));
	if(debug){
		int my_n = (n*8 + sizeof(sc_64))/sizeof(long);
		if(0 > read_mem(pid, my_buff, my_n, libaddr)){
			printf("read_mem failed!\n");
		}
	}

	if (debug)
		printf("executing injection code at 0x%lx\n", codeaddr);

	// calc stack pointer
	// regs.ARM_sp = regs.ARM_sp - n*4 - sizeof(sc);  //32bit
	regs_64.ARM64_sp = regs_64.ARM64_sp - n*8 - sizeof(sc_64);  //64bit

	// call mprotect() to make stack executable
	// regs.ARM_r0 = stack_start; // want to make stack executable 32bit
	regs_64.ARM64_x0 = stack_start; // want to make stack executable 64bit

	//printf("r0 %x\n", regs.ARM_r0);
	// regs.ARM_r1 = stack_end - stack_start; // stack size 32bit
	regs_64.ARM64_x1 = stack_end - stack_start; // stack size 64bit
	//printf("mprotect(%x, %d, ALL)\n", regs.ARM_r0, regs.ARM_r1);
	// regs.ARM_r2 = PROT_READ|PROT_WRITE|PROT_EXEC; // protections 32bit
	regs_64.ARM64_x2 = PROT_READ|PROT_WRITE|PROT_EXEC; // protections

	// normal mode, first call mprotect
	if (nomprotect == 0) {
		if (debug)
			printf("calling mprotect\n");
		//32bit
		// regs.ARM_lr = codeaddr; // points to loading and fixing code
		// regs.ARM_pc = mprotectaddr; // execute mprotect()

		//64bit
		regs_64.ARM64_lr = codeaddr; // points to loading and fixing code
		regs_64.ARM64_pc = mprotectaddr; // execute mprotect()
	}
	// no need to execute mprotect on old Android versions
	else {
		regs.ARM_pc = codeaddr; // just execute the 'shellcode'
	}

	// detach and continue
	// ptrace(PTRACE_SETREGS, pid, 0, &regs);  //32bit
	if(0 > ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov)){
		printf("set registers failed!");
		exit(1);
	}  //64bit

	if(0 > ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT)){
		printf("ptrace detach failed!");
		exit(1);
	}

	if (debug)
		printf("library injection completed!\n");

	return 0;
}
