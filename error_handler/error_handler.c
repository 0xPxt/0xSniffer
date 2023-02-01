#include <stdio.h>
#include <stdlib.h>
#include "error_handler.h"
#include "../globals/globals.h"

void display_error(char *error_message) {
    printf("-=-=-=-=-=-=-= ERROR =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    printf("[ERROR] : %s\n", errbuf);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    exit(1);
}
