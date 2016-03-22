#include <stdio.h>

int main()
{
	printf("Init faking disconnetion\n");
	sleep(1);
	int i = 0;
	for (i = 0; i < 3; i++)
	{
		printf("faking disconnection try %d\n", i);
		sleep(1);
	}
	return 0;
}

