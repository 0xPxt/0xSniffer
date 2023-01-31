#include <stdio.h>
#include <pcap.h> 
#include <sys/socket.h>

#define HAVE_REMOTE
#define DEVICE_LIST_MAX_SIZE 50

int scan_all_available_devices(char**);
void display_error(char *error_message, char *errbuf);

int main (int argc, char** argv) {
    char *devices_list[DEVICE_LIST_MAX_SIZE];
    int num_of_devices = 0;

    num_of_devices = scan_all_available_devices(devices_list);

    for(int i = 0; i < num_of_devices; i++) {
        printf("%s\n", devices_list[i]);
    }
}

int scan_all_available_devices(char **devices_names) {
    pcap_if_t **all_devices;
    char *errbuf;
    int num_of_devices = 0;

    //Find list of nd non-loopback devices
    if(pcap_findalldevs(all_devices, errbuf) == -1) {
        display_error("Error scanning for devices", errbuf);
    }

    num_of_devices = sizeof(all_devices)/sizeof(all_devices[0]);

    //Assing list to argument buffer
    for(int i = 0; i < num_of_devices; i++) {
        devices_names[i] = all_devices[i]->name;
    }

    return num_of_devices;
}

void display_error(char *error_message, char *errbuf) {
    printf("-=-=-=-=-=-=-= ERROR =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    printf("[ERROR] : %s\n", errbuf);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}
