#include <stdio.h>
#include <stdlib.h>

int functionFunction(char* param)
{
	char* localString = "conjunction function";
	int localInt = 0xdeadbeef;
	char localString2[10];

	strcpy(localString2, param);

	return 1;
}

int main(int argc, char* argv[])
{
	char* localString = "main function";
	int localInt = 0x11223344;

	functionFunction(argv[1]);

	return 0;
}
