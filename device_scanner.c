#include <stdio.h>
#define HAVE_REMOTE
#include <pcap.h> 
#include <sys/socket.h>

int main (int argc, char** argv) {
    pcap_if_t **all_devices;
    char *errbuf;
    int num_of_devices = 0;
    
    //Add list of found non-loopback devices to all_devices
    if(pcap_findalldevs(all_devices, errbuf) == -1) {
        printf("Error scanning for devices\n");
        printf("Error : %s\n", errbuf);
    }

    num_of_devices = sizeof(all_devices)/sizeof(all_devices[0]);

    //Print name to stdout
    for(int i = 0; i < num_of_devices; i++) {
        printf("%s\n", all_devices[i]->name);
    }

}
