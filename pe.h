#ifndef PE_H_
#define PE_H_

typedef unsigned char BYTE, *PBYTE;
typedef unsigned short WORD, *PWORD;
typedef unsigned long DWORD, *PDWORD;

#include <windows.h>
#include <stddef.h>

struct peimg
{
	size_t size;
	void *buf;
	PIMAGE_DOS_HEADER pdos_hdr;
	PIMAGE_NT_HEADERS pnt_hdr;
	PIMAGE_SECTION_HEADER psection_hdr;
};

struct pemapped
{
	size_t size;
	void *buf;
	IMAGE_DOS_HEADER *pdos_hdr;
	IMAGE_NT_HEADERS *pnt_hdr;
	IMAGE_SECTION_HEADER *psection_hdr;
};

#define PEERR_NONE                   0
#define PEERR_FILE_ACCESS_FAILURE    0x00010000
#define PEERR_INVALID_MZHDR          0x00020000
#define  PEERR_BAD_MZMAGIC           (PEERR_INVALID_MZHDR | 1)
#define PEERR_INVALID_NTHDR          0x00030000
#define  PEERR_BAD_OPTIONAL_SIZE     (PEERR_INVALID_NTHDR | 1)
#define  PEERR_BAD_IMAGE_SIZE        (PEERR_INVALID_NTHDR | 2)
#define  PEERR_BAD_HDR_SIZE          (PEERR_INVALID_NTHDR | 3)

union pe_report
{
	int n;
};

#define PE_INVALID_SECTION_ID ((unsigned)-1)

extern int peimg_load(struct peimg **u, char const *path);
extern void peimg_save(struct peimg *u, char const *path);
extern void peimg_free(struct peimg *u);
extern int peimg_parse(struct peimg *u);
extern int peimg_check(struct peimg *u);

// extern DWORD peimg_has_scn(struct peimg *u, unsigned id);
#define peimg_has_scn(u, id) (id < u->pnt_hdr->FileHeader.NnumberOfSections)
// extern DWORD peimg_get_scn(struct peimg *u, unsigned id);
#define peimg_get_scn(u, id) (u->section_hdr[id].PointerToRawData)
// extern int peimg_is_section_inited(struct peimg *u, unsigned id);
#define peimg_is_scn_inited(u, id) (int)(peimg_get_scn(u, id) != 0)

extern int pemapped_load(struct pemapped **u, char const *path);
extern void pemapped_dump(struct pemapped *u, char const *path);
extern void pemapped_dup(struct pemapped **u, struct pemapped *s);
extern void pemapped_free(struct pemapped *u);
extern int pemapped_check(struct peimg *u);
extern int pemapped_map(struct pemapped **u, struct peimg *s);
//extern int pemapped_parse(struct pemapped *u);
extern unsigned pemapped_find_scn(struct pemapped *u, DWORD RVA);
extern int pemapped_rebuild_pehdr(struct pemapped *u);

// extern int pemapped_has_scn(struct pemapped *u, unsigned id);
#define pemapped_has_scn(u, id)	(id < u->pnt_hdr->FileHeader.NnumberOfSections)
// extern DWORD pemapped_get_scn(struct pemapped *u, unsigned id);
#define pemapped_get_scn(u, id)	(u->section_hdr[id].VirtualAddress)

#endif /* PE_H_ */
