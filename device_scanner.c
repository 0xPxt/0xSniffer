#include <stdio.h>
#include <pcap.h>

#if _WIN32
#else
#include <sys/socket.h>
#endif

#define HAVE_REMOTE
#define DEVICE_LIST_MAX_SIZE 50

char errbuf[PCAP_ERRBUF_SIZE];

int scan_all_available_devices(char**);
void display_error(char *error_message);

int main (int argc, char** argv) {
    char *devices_list[DEVICE_LIST_MAX_SIZE];
    int num_of_devices = 0;
    int errNum = 0;

    // Initialize library to use local encoding
    errNum = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (errNum == PCAP_ERROR) {
        display_error("Could not initialize pcap library!");
    }

    num_of_devices = scan_all_available_devices(devices_list);

    for(int i = 0; i < num_of_devices; i++) {
        printf("%s\n", devices_list[i]);
    }
}

int scan_all_available_devices(char **devices_names) {
    pcap_if_t *all_devices;
    pcap_if_t *currentDevice;
    int num_of_devices = 0;

    //Find list of nd non-loopback devices
    if(pcap_findalldevs(&all_devices, errbuf) == PCAP_ERROR) {
        display_error("Error scanning for devices");
    }

    //Assing list to argument buffer
    currentDevice = all_devices;
    while(currentDevice != NULL) {
        devices_names[num_of_devices++] = currentDevice->name;
        currentDevice = currentDevice->next;
    }

    return num_of_devices;
}

void display_error(char *error_message) {
    printf("-=-=-=-=-=-=-= ERROR =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    printf("[ERROR] : %s\n", errbuf);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    exit(1);
}
