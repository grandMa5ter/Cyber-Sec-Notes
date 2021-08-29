#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
/* run this program using the console pauser or add your own getch, system("pause") or input loop */
 
typedef struct salesItem 
{
	char description[20];
	int productNumber;
	float price;
	int quantity;
 } myItem;
 
 struct salesItem *pMyItem;
 
int main(int argc, char *argv[]) 
{
	long* hHeap = HeapCreate(0x00040000, 0, 0);
	char *buff1, *buff2, *buff3;
	
	buff1 = HeapAlloc(hHeap, 0, 0x10);
	buff2 = HeapAlloc(hHeap, 0, 0x100);
	struct salesItem myItem;
	
	strcpy(myItem.description, "Sample Item");
	myItem.productNumber=1;
	myItem.price=1.00;
	myItem.quantity=1;
	
	memcpy(buff2, &myItem, sizeof(struct salesItem));
	
	strcpy(buff1, argv[1]); // possibly buffer overflow vuln

	// display possibly modified item
	pMyItem = (struct salesItem*)buff2;
	printf("My Item is now: %s %f %d", pMyItem->description, pMyItem->price, pMyItem->quantity);
	
	HeapFree(hHeap, 0, buff2); // could seg fault if buff1 is overflowed
	HeapFree(hHeap, 0, buff1);
	
	return 0;
}
