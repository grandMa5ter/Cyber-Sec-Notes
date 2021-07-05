#include <stdio.h>
#include <stdlib.h>
#include <windows.h>



/* run this program using the console pauser or add your own getch, system("pause") or input loop */

// global variables that are initialized
char myGlobalString[16]="global";
FARPROC gfp1=0; //printf
FARPROC gfp2=0; //strcpy

int myGlobalInt=0xdeadbeef;

int main(int argc, char *argv[]) 
{
	HMODULE hLib;
	hLib = LoadLibrary("msvcrt.dll");
	
	gfp1=GetProcAddress(hLib, "printf");
	gfp2=GetProcAddress(hLib, "strcpy");
	
	(gfp2)(myGlobalString,argv[1]); // may overflow and overwrite gfp1 (and more)
	(gfp1)("myGlobalString contains %s", myGlobalString);
	
	return 0;
}
