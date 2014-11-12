#include "PE.h"
#include "stdio.h"
#include "malloc.h"

#define _OFFSET_BYBYTE(p, off) ((PBYTE)(p) + off)
#define _ROUND_TO(x, a) ((x) & ~(a-1))

/*
  PE Image File
*/

int peimg_load(struct peimg **u, char const *path)
{
	FILE *fi = fopen(path, "rb");
	int retval;
	if (!fi)
		return PEERR_FILE_ACCESS_FAILURE;
	*u = (struct peimg *)malloc(sizeof(struct peimg));
	fseek(fi, SEEK_END, 0);
	(*u)->size = ftell(fi);
	fseek(fi, SEEK_SET, 0);
	(*u)->buf = malloc((*u)->size);
	fread((*u)->buf, 1, (*u)->size, fi);
	fclose(fi);
	retval = peimg_parse(*u);
	if (retval != PEERR_NONE)
	{
		peimg_free(*u);
		*u = NULL;
	}
	return retval;
}

void peimg_save(struct peimg *u, char const *path)
{
	FILE *fo = fopen(path, "wb");
	if (!fo)
		return ;
	fwrite(u->buf, 1, u->size, fo);
	fclose(fo);
}

void peimg_free(struct peimg *u)
{
	free(u->buf);
	free(u);	
}

int peimg_parse(struct peimg *u)
{
	size_t t;
	WORD n;
	u->pdos_hdr = (PIMAGE_DOS_HEADER)(u->buf);
	t = u->pdos_hdr->e_lfanew;
	if (u->size < t + sizeof(IMAGE_NT_HEADERS))
		return PEERR_INVALID_MZHDR;
	u->pnt_hdr = (PIMAGE_NT_HEADERS)_OFFSET_BYBYTE(u->buf, u->pdos_hdr->e_lfanew);
	n = u->pnt_hdr->FileHeader.NumberOfSections;
	if (n == 0)
	{
		u->psection_hdr = NULL;
		return PEERR_NONE;
	}
	t += offsetof(IMAGE_NT_HEADERS, OptionalHeader)
		+ u->pnt_hdr->FileHeader.SizeOfOptionalHeader;
	if (u->size < t + n * sizeof(IMAGE_SECTION_HEADER))
	{
		u->psection_hdr = NULL;
		return PEERR_BAD_OPTIONAL_SIZE;
	}
	u->psection_hdr = (PIMAGE_SECTION_HEADER)_OFFSET_BYBYTE(u->buf, t);
	return PEERR_NONE;
}

int peimg_check(struct peimg *u)
{/*todo*/
	return PEERR_FILE_ACCESS_FAILURE;
}

/*
  PE Mapped
*/

int pemapped_load(struct pemapped **u, char const *path)
{
	FILE *fi = fopen(path, "rb");
	DWORD t, pe_loc, i, fl_align, section_align;
	IMAGE_SECTION_HEADER *cur_hdr;
	if (!fi)
		return PEERR_FILE_ACCESS_FAILURE;
	*u = (struct pemapped *)malloc(sizeof(struct pemapped));
	fseek(fi, offsetof(IMAGE_DOS_HEADER, e_lfanew), SEEK_SET);
	fread(&pe_loc, sizeof(DWORD), 1, fi);
	fseek(fi, pe_loc + offsetof(IMAGE_NT_HEADERS, OptionalHeader.SizeOfImage), SEEK_SET);
	fread(&t, sizeof(DWORD), 1, fi);
	(*u)->buf = malloc(t);
	(*u)->size = t;
	memset((*u)->buf, 0, t);
	/* map headers */
	fseek(fi, pe_loc + offsetof(IMAGE_NT_HEADERS, OptionalHeader.SizeOfHeaders), SEEK_SET);
	fread(&t, sizeof(DWORD), 1, fi);
	fseek(fi, 0, SEEK_SET);
	fread((*u)->buf, 1, t, fi);
	/* parse basic headers */
	(*u)->pdos_hdr = (PIMAGE_DOS_HEADER)(*u)->buf;
	(*u)->pnt_hdr = (PIMAGE_NT_HEADERS)_OFFSET_BYBYTE((*u)->buf, pe_loc);
	(*u)->psection_hdr = IMAGE_FIRST_SECTION((*u)->pnt_hdr);
	/* map sections */
	t = (*u)->pnt_hdr->FileHeader.NumberOfSections;
	cur_hdr = (*u)->psection_hdr;
	fl_align = (*u)->pnt_hdr->OptionalHeader.FileAlignment;
	section_align = (*u)->pnt_hdr->OptionalHeader.SectionAlignment;
	for (i = 0; i < t; ++i)
	{
		if (cur_hdr->SizeOfRawData == 0)
			continue;
		// todo upper round or lower round test
		fseek(fi, _ROUND_TO(cur_hdr->PointerToRawData, fl_align), SEEK_SET);
		fread(
			_OFFSET_BYBYTE((*u)->buf, _ROUND_TO(cur_hdr->VirtualAddress, section_align)),
			1,
			cur_hdr->SizeOfRawData,
			fi);
		++cur_hdr;
	}
	fclose(fi);
	return PEERR_NONE;
}

void pemapped_dump(struct pemapped *u, char const *path)
{
	FILE *fo = fopen(path, "wb");
	if (!fo)
		return ;
	fwrite(u->buf, 1, u->size, fo);
	fclose(fo);
}

void pemapped_dup(struct pemapped **u, struct pemapped *s)
{
	(*u) = (struct pemapped *)malloc(sizeof(struct pemapped));
	(*u)->size = s->size;
	(*u)->buf = malloc(s->size);
	memcpy((*u)->buf, s->buf, s->size);
	(*u)->pdos_hdr = (PIMAGE_DOS_HEADER)(*u)->buf;
	(*u)->pnt_hdr = (PIMAGE_NT_HEADERS)_OFFSET_BYBYTE((*u)->buf, (*u)->pdos_hdr->e_lfanew);
	(*u)->psection_hdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION((*u)->pnt_hdr);
}

void pemapped_free(struct pemapped *u)
{
	free(u->buf);
	free(u);
}

int pemapped_check(struct peimg *u)
{/*todo*/
	return PEERR_NONE;
}

int pemapped_map(struct pemapped **u, struct peimg *s)
#define _ROUND_TO(x, a) ((x) & ~(a-1))
{
	DWORD t, pe_loc, i, fl_align, section_align;
	IMAGE_SECTION_HEADER *cur_hdr;
	*u = (struct pemapped *)malloc(sizeof(struct pemapped));
	pe_loc = s->pdos_hdr->e_lfanew;
	t = s->pnt_hdr->OptionalHeader.SizeOfImage;
	(*u)->buf = malloc(t);
	(*u)->size = t;
	memset((*u)->buf, 0, t);
	/* map headers */
	memcpy((*u)->buf, s->buf, s->pnt_hdr->OptionalHeader.SizeOfHeaders);
	/* parse basic headers */
	(*u)->pdos_hdr = (PIMAGE_DOS_HEADER)(*u)->buf;
	(*u)->pnt_hdr = (PIMAGE_NT_HEADERS)_OFFSET_BYBYTE((*u)->buf, pe_loc);
	(*u)->psection_hdr = IMAGE_FIRST_SECTION((*u)->pnt_hdr);
	/* map sections */
	t = s->pnt_hdr->FileHeader.NumberOfSections;
	cur_hdr = s->psection_hdr;
	fl_align = s->pnt_hdr->OptionalHeader.FileAlignment;
	section_align = s->pnt_hdr->OptionalHeader.SectionAlignment;
	for (i = 0; i < t; ++i)
	{
		if (cur_hdr->SizeOfRawData == 0)
			continue;
		// todo upper round or lower round test
		memcpy(_OFFSET_BYBYTE((*u)->buf, _ROUND_TO(cur_hdr->VirtualAddress, section_align)),
			_OFFSET_BYBYTE((*u)->buf,  _ROUND_TO(cur_hdr->PointerToRawData, fl_align)),
			cur_hdr->SizeOfRawData);
		++cur_hdr;
	}
	return PEERR_NONE;
}

unsigned pemapped_find_scn(struct pemapped *u, DWORD RVA)
{
	unsigned i, n = u->pnt_hdr->FileHeader.NumberOfSections;
	for (i = 0; i < n; ++i)
		if (RVA < u->psection_hdr[n].VirtualAddress)
			return (i == 0 ? PE_INVALID_SECTION_ID : i - 1);
	return n;
}

int pemapped_rebuild_pehdr(struct pemapped *u)
{
	unsigned i, n = u->pnt_hdr->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *cur_hdr = u->psection_hdr;
	for (i = 0; i < n; ++i)
	{
		cur_hdr->PointerToRawData = cur_hdr->VirtualAddress;
		++cur_hdr;
	}
	return PEERR_NONE;
}
