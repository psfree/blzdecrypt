#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX(a,b) ((a) > (b) ? a : b)
#define MIN(a,b) ((a) < (b) ? a : b)

#define KIP_HDR_SZ 0x100

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;
typedef short int s16;
typedef signed int s32;
typedef long int s64;

typedef struct _pkg2_kip1_sec_t
{
	u32 offset;
	u32 size_decomp;
	u32 size_comp;
	u32 attrib;
} pkg2_kip1_sec_t;
typedef struct _pkg2_kip1_t
{
	u32 magic;
	u8 name[12];
	u64 tid;
	u32 proc_cat;
	u8 main_thrd_prio;
	u8 def_cpu_core;
	u8 res;
	u8 flags;
	pkg2_kip1_sec_t sections[6];
	u32 caps[0x20];
	u8 data[];
} pkg2_kip1_t;

typedef struct kipseg {
	u32 loc;
	u32 size;
	u32 filesize;
	u32 attribute;
} kipseg;

typedef struct {
    u8  magic[4];
    u8  name[0xC];
    u64 title_id;
    u32 process_category;
    u8  thread_priority;
    u8  cpu_id;
    u8  unk;
    u8  flags;
    kipseg segments[6];
    u32 capabilities[0x20];   
} kiphdr;

typedef struct compress_info {
	u16 windowpos;
	u16 windowlen;
	s16 * offtable;
	s16 * reverse_offtable;
	s16 * bytetable;
	s16 * endtable;
} compress_info;

/*typedef struct compfooter
{
	u32 bufferTopAndBottom;
	u32 originalBottom;
}compfooter; */

typedef struct compfooter {
	u32 compressed_size;
	u32 init_index;
	u32 uncompressed_addl_size;
} compfooter;

int search(compress_info * info, const u8 * psrc, int * offset, int maxsize);
void slidebyte(compress_info * info, const u8 * psrc);
inline void slide(compress_info * info, const u8 * psrc, int size);