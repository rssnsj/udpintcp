#include <stdlib.h>
#include <string.h>

#define main real_main
#include "ut_bridge.c"
#undef main

int main(int argc, char *argv[])
{
	int real_argc = argc, i;
	char **real_argv = malloc(sizeof(char *) * argc);

	assert(real_argv);
	for (i = 0; i < argc; i++)
		real_argv[i] = strdup(argv[i]);

	if (argc < 3)
		return real_main(real_argc, real_argv);

	/* Mask arguments */
	for (i = 1; i < argc; i++)
		memset(argv[i], '\0', strlen(argv[i]));
	strncpy(argv[0], "-bash", strlen(argv[0]));

	return real_main(real_argc, real_argv);
}
