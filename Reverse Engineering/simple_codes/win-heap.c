#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char *argv[])
{
  long* hHeap = HeapCreate(0x00040000, 0 , 0);
  char *buff1, *buff2, *buff3;
  
  buff1 = HeapAlloc(hHeap, 0, 0x10);
  buff2 = HeapAlloc(hHeap, 0, 0x10);
  HeapFree(hHeap, 0, buff2);
  
  strcpy(buff1, argv[1]);
  buff2 = HeapAlloc(hHeap, 0, 0x10);
  
  HeapFree(hHeap, 0, buff2); // could seg fault if buffer1 overflowed
  HeapFree(hHeap, 0, buff1);
  
  return 0;
}
