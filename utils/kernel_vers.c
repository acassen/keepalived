#include <linux/version.h>
#include <stdio.h>
#include <string.h>

int kernel_vers[] = {
#include "kernel_vers_nos.h"
	KERNEL_VERSION(0,0,0)
};

int
main (int argc, char **argv)
{
	int i;
	int last_ok = 0;

	for (i = 0; kernel_vers[i]; i++) {
		if (kernel_vers[i] <= LINUX_VERSION_CODE)
			last_ok = kernel_vers[i];
		else
			break;
	}

	if (argc >= 2 && !strcmp(argv[1], "-n"))
		printf("%d\n", last_ok);
	else {
		printf("%d.%d", (last_ok >> 16) & 0xff, (last_ok >> 8) & 0xff);
		if (last_ok & 0xff)
			printf(".%d", last_ok & 0xff);
		printf("\n");
	}
}
