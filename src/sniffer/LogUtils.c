
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