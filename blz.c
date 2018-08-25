#include "blz.h"


s64 Align(s64 data, s64 alignment){
	return (data + alignment - 1) / alignment * alignment;
}


void init_info(compress_info * info, void * buf) {
	info->windowpos = 0;
	info->windowlen = 0;
	info->offtable = (s16 *)buf;
	info->reverse_offtable = (s16 *)(buf) + 4098;
	info->bytetable = (s16 *)(buf) + 4098*2;
	info->endtable = (s16 *)(buf)+4098*2+256;
	for(int i=0; i< 256; i++){
		info->bytetable[i] = -1;
		info->endtable[i] = -1;
	}
}

int search(compress_info * info, const u8 * psrc, int * noffset, int maxsize) {
		if(maxsize < 3)
			return 0;
		const u8 * psearch = NULL;
		int size = 2;
		const u16 windowpos = info->windowpos;
		const u16 windowlen = info->windowlen;
		s16 * reverse_offtable = info->reverse_offtable;
		for(s16 offset = info->endtable[*(psrc -1)]; offset != -1; offset = reverse_offtable[offset]) {
			if(offset < windowpos)
				psearch = psrc + windowpos - offset;
			else
				psearch = psrc + windowlen + windowpos - offset;
			if(psearch - psrc < 3)
				continue;
			if(*(psearch - 2) != *(psrc - 2) || *(psearch -3) != *(psrc -3))
				continue;
			int max = (int) MIN(maxsize, (psearch-psrc));
			int cursize = 3;
			while(cursize < max && *(psearch - cursize - 1) == *(psrc - cursize - 1))
				cursize++;
			if(cursize > size) {
				size = cursize;
				*noffset = (int) (psearch-psrc);
				if(size == maxsize)
					break;
			}
		
		}
		if(size < 3)
			return 0;
		return size;
}

void slidebyte(compress_info * info, const u8 * psrc) {
	u8 indata = *(psrc - 1);
	u16 insertoff = 0;
	const u16 windowpos = info->windowpos;
	const u16 windowlen = info->windowlen;
	s16 * offtable = info->offtable;
	s16 * reverse_offtable = info->reverse_offtable;
	s16 * bytetable = info->bytetable;
	s16 * endtable = info->endtable;
	if(windowlen == 4098) {
		u8 outdata = *(psrc + 4097);
		if((bytetable[outdata] = offtable[bytetable[outdata]]) == -1)
			endtable[outdata] = -1;
		else
			reverse_offtable[bytetable[outdata]] = -1;
		insertoff = windowpos;
			
	}
	else
		insertoff = windowlen;
	
	s16 noff = endtable[indata];
	if(noff == -1)
		bytetable[indata] = insertoff;
	else
		offtable[noff] = insertoff;
	endtable[indata] = insertoff;
	offtable[insertoff] = -1;
	reverse_offtable[insertoff] = noff;
	if(windowlen == 4098)
		info->windowpos = (windowpos + 1) % 4098;
	else
		info->windowlen++;
}

void slide(compress_info * info, const u8 * psrc, int size) {
	for(int i=0; i<size; i++)
		slidebyte(info, psrc--);
}

int result = 0;

char * blz_compress(unsigned char * decompressed, u32 * isize) {
	result = 1;
	u8 * dest = malloc(*isize+1);
	u32 classic_size = *isize;

	u32 comp_size = *isize;
	
	if(*isize > sizeof(compfooter) && comp_size >= *isize) {
		
		u32 bufsize = (4098 + 4098 + 256 + 256) * sizeof(s16);
		u8 workbuf[bufsize];
		
		u32 headerSize = 4;
		do {
			compress_info info;
			init_info(&info, workbuf);
			const int maxsize = 0xF + 3;
			const u8 * psrc = decompressed + *isize;
			u8 * pdst = dest + *isize;
			while(psrc - decompressed > 0 && pdst - dest > 0) {
				u8 * pflag = --pdst;
				*pflag = 0;
				for(int i=0; i<8; i++) {
					int noff = 0;
					u32 t1 = MIN(maxsize, psrc - decompressed);
					t1 = MIN(t1, decompressed + *isize - psrc);
					int nsize = search(&info, psrc, &noff, t1);
					if(nsize <3) {
						if(pdst - dest < 1){
							result = -1;
							break;
						}
						slide(&info, psrc, 1);
						*--pdst = *--psrc;
					}
					else {
						if(pdst - dest < 2) {
							result = -2;
							break;
						}
						*pflag |= 0x80 >> i;
						slide(&info, psrc, nsize);
						psrc -= nsize;
						nsize -= 3;
						*--pdst = (nsize << 4 & 0xF0) | ((noff -3) >> 8 & 0x0F);
						*--pdst = (noff - 3) & 0xFF;
					}
					if(psrc - decompressed <= 0)
						break;
				}
				if(!result)
					break;
				
			}
			if(!result)
				break;
			comp_size = dest + *isize - pdst;
		} while(0);
	}
	else
		result = -3;
	if(result>0) {
		u32 origsize = *isize;
		u8 *compbuffer = dest + origsize - comp_size;
		u32 compbuffersize = comp_size;
		u32 origsafe = 0;
		u32 compresssafe = 0;
		int over =0;
		while(origsize > 0) {
			u8 flag = compbuffer[--compbuffersize];
			for(int i=0; i<8; i++) {
				if((flag << i & 0x80)==0) {
					compbuffersize--;
					origsize--;
				}
				else {
					int nsize = (compbuffer[--compbuffersize] >> 4 & 0x0F) + 3;
					compbuffersize--;
					origsize -= nsize;
					if(origsize < compbuffersize) {
						origsafe = origsize;
						compresssafe = compbuffersize;
						over = 1;
						break;
					}
					
				}
				if(origsize <=0)
					break;
			}
			if(over)
				break;

		}
		u32 fcompsize = comp_size - compresssafe;
		u32 padoffset = origsafe + fcompsize;
		u32 compfooteroff = (u32) Align(padoffset, 4);
		comp_size = compfooteroff + sizeof(compfooter);
		u32 top = comp_size - origsafe;
		u32 bottom = comp_size - padoffset;
		if(comp_size >= classic_size || top > 0xFFFFFF){
			result = 0;
		}
		else {
			memcpy(dest, decompressed, origsafe);
			memmove(dest + origsafe, compbuffer + compresssafe, fcompsize);
			memset(dest + padoffset, 0xFF, compfooteroff - padoffset);
			compfooter * fcompfooter = (compfooter *) (dest + compfooteroff);
			fcompfooter->compressed_size = top;
			fcompfooter->init_index = comp_size - padoffset;
			fcompfooter->uncompressed_addl_size = classic_size - comp_size;
		}
		*isize = comp_size;
		return dest;
		
	}
	
	

}


char * blz_decompress(unsigned char * compressed, u32 * isize) {
	u32 size = *isize;
	u32 compressed_size;
	u32 init_index;
	u32 uncompressed_addl_size;
	u32 f_factor = 0x1000;
	
	memcpy(&compressed_size, compressed+size - 0xC, 4);
	memcpy(&init_index, compressed+size - 0x8, 4);
	memcpy(&uncompressed_addl_size, compressed+size - 0x4, 4);
	
	u32 decompressed_size = compressed_size + uncompressed_addl_size;
	unsigned char * decomp = malloc(decompressed_size+f_factor);
	memcpy(decomp, compressed, size);
	for(int i=size; i<decompressed_size; i++)
		decomp[i]=0x0;
	if(size!=compressed_size) {
		memcpy(decomp, compressed, size-compressed_size);
		decomp += size-compressed_size;
		compressed +=size-compressed_size;
	}
	u32 index = compressed_size - init_index;
	
	u32 outindex = decompressed_size;
	while(outindex > 0) {
		index -= 1;
		unsigned char control;
		memcpy(&control, compressed+index,1);
		for(int i=0; i<8; i++) {
			if(control & 0x80) {
				if(index < 2) {
					//printf("ERROR: Compression out of bounds\n");
					return -1;
				}
				index -= 2;
				unsigned short int segmentoffset = compressed[index] | (compressed[index+1] <<8);
				u32 segmentsize = ((segmentoffset >> 12) & 0xF) + 3;
				segmentoffset &= 0x0FFF;
				segmentoffset +=2;
				if(outindex < segmentsize) {
					//printf("ERROR: Compression out of bounds, outindex<segsize\n");
					return -1;
				}
				for(int j=0; j<segmentsize; j++) {
					if(outindex +segmentoffset >= decompressed_size) {
						//printf("ERROR: Compression out of bounds, 3\n");
						return -1;
					}
					char data = decomp[outindex+segmentoffset];
					outindex -= 1;
					decomp[outindex] = data;
				}
			}
			else{
				if(outindex < 1){
					//printf("ERROR: compression out of bounds, 4 \n");
					return 0;
				}
				outindex -= 1;
				index -= 1;
				decomp[outindex] = compressed[index];
			}
			control <<= 1;
			control &= 0xFF;
			if(!outindex)
				break;
		}
	}
	*isize = decompressed_size + (size-compressed_size);
	return decomp - (size-compressed_size);
}

char * kip_comp(char * bytes, u32 * sz) {
	kiphdr header;
	kipseg * text_h;
	kipseg * ro_h;
	kipseg * data_h;
	memcpy(&header, bytes, 0x100);
	if(strncmp(header.magic, "KIP1", 4)) {
		printf("KIP1 magic is missing, abort %s\n", header.magic);
		return NULL;
	}
	text_h = &header.segments[0];
	ro_h = &header.segments[1];
	data_h = &header.segments[2];
	
	u32 toff = sizeof(kiphdr);
	u32 roff = toff + text_h->filesize;
	u32 doff = roff + ro_h->filesize;
	u32 bsssize;
	memcpy(&bsssize, bytes+0x18, 4);
	char * text = malloc(text_h->filesize);
	memcpy(text, bytes+toff, text_h->filesize);
	char * ro = malloc(ro_h->filesize);
	memcpy(ro, bytes+roff, ro_h->filesize);
	char * data = malloc(data_h->filesize);
	memcpy(data, bytes+doff, data_h->filesize);
	
	text = blz_compress(text, &text_h->filesize);
	ro = blz_compress(ro, &ro_h->filesize);
	data = blz_compress(data, &data_h->filesize);
	
	u32 totalsize = sizeof(kiphdr)+text_h->filesize+ro_h->filesize+data_h->filesize;
	char * out = malloc(totalsize+1);
	
	header.flags |= 7; //set first 3 bits to 1
	
	memcpy(out, &header, sizeof(kiphdr));
	memcpy(out+sizeof(kiphdr), text, text_h->filesize);
	memcpy(out+sizeof(kiphdr)+text_h->filesize, ro, ro_h->filesize);
	memcpy(out+sizeof(kiphdr)+text_h->filesize+ro_h->filesize,data, data_h->filesize); 
	
	*sz = totalsize;
	return out;
}

char * kip_decomp(char * bytes, int * sz) {
	kiphdr header;
	kipseg * text_h;
	kipseg * ro_h;
	kipseg * data_h;
	
	memcpy(&header, bytes, 0x100); 
	if(strncmp(header.magic, "KIP1", 4)) {
		printf("KIP1 magic is missing, abort %s\n", header.magic);
		return NULL;
	}
	text_h = &header.segments[0];
	ro_h = &header.segments[1];
	data_h = &header.segments[2];

	u32 toff = sizeof(kiphdr);
	u32 roff = toff + text_h->filesize;
	u32 doff = roff + ro_h->filesize;
	u32 bsssize;
	memcpy(&bsssize, bytes+0x18, 4);
	char * text = malloc(text_h->filesize+1);
	memcpy(text, bytes+toff, text_h->filesize);
	char * ro = malloc(ro_h->filesize+1);
	memcpy(ro, bytes+roff, ro_h->filesize);
	char * data = malloc(data_h->filesize+1);
	memcpy(data, bytes+doff, data_h->filesize);
	
	text = blz_decompress(text, &text_h->filesize);
	ro = blz_decompress(ro, &ro_h->filesize);
	data = blz_decompress(data, &data_h->filesize);
		
	u32 totalsize = sizeof(kiphdr)+text_h->filesize+ro_h->filesize+data_h->filesize;
	char * out = malloc(totalsize+1);
	
	header.flags &= ~7;  //AND NOT 7 = zero first 3 bits
	printf("%x %x\n", sizeof(kiphdr), sizeof(pkg2_kip1_t));
	memcpy(out, &header, sizeof(kiphdr));
	memcpy(out+sizeof(kiphdr), text, text_h->filesize);
	memcpy(out+sizeof(kiphdr)+text_h->filesize, ro, ro_h->filesize);
	memcpy(out+sizeof(kiphdr)+text_h->filesize+ro_h->filesize,data, data_h->filesize); 
	
	free(text);
	free(ro);
	free(data);
	
	*sz = totalsize;
	return out;
}
int test1() {
	FILE *fp;
	fp = fopen("sss.kip1", "rb");
	if(fp==NULL)
		return -1;
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char * bytes = malloc(fsize +1);
	fread(bytes, fsize, 1, fp);
	fclose(fp);
	printf("Read %ld bytes from KIP\n", fsize);
	u32 size;
	char * out= kip_comp(bytes, &size);
	fp = fopen("FSnew100comp.kip1", "wb");
	fwrite(out, 1, size, fp);
	fclose(fp);
	return 0;
	
}
static u32 calcKipSize(pkg2_kip1_t *kip1) {
    u32 size = sizeof(pkg2_kip1_t);
    for (u32 j = 0; j < 6; j++)
        size += kip1->sections[j].size_comp;
    return size;
}

int main() {
	FILE *fp;
	fp = fopen("FS410.kip1", "rb");
	if(fp==NULL)
		return -1;
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char * bytes = malloc(fsize +1);
	fread(bytes, fsize, 1, fp);
	fclose(fp);
	printf("Read %ld bytes from KIP\n", fsize);
	u32 size = fsize;
	//pkg2_kip1_t *kip1 = (pkg2_kip1_t *)bytes;
	//u32 lol = calcKipSize(kip1);
	//printf("%x, %x \n", lol, size);
	char * out= kip_decomp(bytes, &size);
	fp = fopen("FS410_decomp.kip1", "wb");
	fwrite(out, 1, size, fp);
	fclose(fp);
	free(out);
	free(bytes);
	//test1();
	return 0;
}