
#include "LogUtils.h"

#include <stdlib.h>

void LogUtils_ClearScreen() {
    system("cls");
}

void LogUtils_DisplayBanner() {
    LogUtils_ClearScreen();

    printf("\n");
    printf("\n");
    printf("  ___        ____     _ ______    \n");   
    printf(" / _ \\__ __ / __/__  (_) _/ _/__ ____\n");
    printf("/ // /\\ \\ /_\\ \\/ _ \\/ / _/ _/ -_) __/\n");
    printf("\\___//_\\_\\/___/_//_/_/_//_/ \\__/_/ \n");  
    printf("\n");
    printf("\n");

    printf("\n");
}

void LogUtils_RequestFileName(char *fileName) {
    printf("Please enter the name of the file [filename.txt] : ");
    scanf("%s", fileName);
}

void LogUtils_RequestPacketID(int *id) {
    printf("Please enter the ID of the packet you wish to dump : ");
    scanf("%d", id);
}

