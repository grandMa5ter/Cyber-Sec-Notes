#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int func1(char* theString)
{
	printf(theString);

	return 0;
}

int passwordIsValid(char* password, char* message)
{
	if (strcmp("AAAAAAAA", password))
	{
		func1(message);
		return 1;
	}
	else
	{
		func1(message);
		return 0;
	}
}

int main(int argc, char** argv)
{
	printf("This program prints what the user inputs.\n");
	if (argc >2)
		passwordIsValid(argv[2], argv[1]);

	return 0;
}
