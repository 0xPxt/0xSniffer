#include <stdio.h>
#include <stdlib.h>
#include "../device_scanner/device_scanner.h"
#include "../error_handler/error_handler.h"
#include "../globals/globals.h"

char* static_menu(char** devices_list, int num_of_devices);
void clear_screen();
void display_banner();

int main (int argc, char** argv) {
    char *devices_list[DEVICE_LIST_MAX_SIZE];
    int num_of_devices = 0;
    int errNum = 0;
    char *device_selected;

    #if _WIN32
    // Initialize library to use local encoding
    errNum = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (errNum == PCAP_ERROR) {
        pcap_error("Could not initialize pcap library!");
    }
    #endif

    num_of_devices = scan_all_available_devices(devices_list);

    device_selected = static_menu(devices_list, num_of_devices);
}

char* static_menu(char** devices_list, int num_of_devices) {
    int selection = -1;

    clear_screen();

    display_banner();

    //Loop until user selects a valid option
    while ((selection < 0) || (selection > num_of_devices)) {
        printf("\n");
        printf("Select one of your devices to sniff the network :\n");
        printf("\n");

        for(int i = 0; i < num_of_devices; i++) {
            printf("-= %d =- %s\n", i, devices_list[i]);
        }

        printf("\n");
        printf("Enter the number and press ENTER :\n");
        scanf("%d", &selection);

        if ((selection >= 0) && (selection < num_of_devices)) {
            //Option chosen correctly
            printf("You have selected : %s\n", devices_list[selection]);
            return devices_list[selection];
        }

        clear_screen();

        display_banner();

        display_error("Please choose a valid number");
    }
}

void clear_screen() {
    system("clear||cls");
}

void display_banner() {
    printf("\n");
    printf("\n");
    printf("╔═══╗    ╔═══╗       ╔═╗ ╔═╗\n");
    printf("║╔═╗║    ║╔═╗║       ║╔╝ ║╔╝\n");
    printf("║║ ║║╔╗╔╗║╚══╗╔═╗ ╔╗╔╝╚╗╔╝╚╗╔══╗╔═╗\n");
    printf("║║ ║║╚╬╬╝╚══╗║║╔╗╗╠╣╚╗╔╝╚╗╔╝║╔╗║║╔╝\n");
    printf("║╚═╝║╔╬╬╗║╚═╝║║║║║║║ ║║  ║║ ║║═╣║║\n");
    printf("╚═══╝╚╝╚╝╚═══╝╚╝╚╝╚╝ ╚╝  ╚╝ ╚══╝╚╝\n");
    printf("\n");
    printf("\n");
}
