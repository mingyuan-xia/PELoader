#include "pe.h"

int main(int argc, char *argv[])
{
	struct pemapped *u;
	pemapped_load(&u, "test_case.exe");
	pemapped_dump(u, "test_case_mapped.exe");
	pemapped_rebuild_pehdr(u);
	pemapped_dump(u, "test_case_rebuilt.exe");
	pemapped_free(u);
	return 0;
}