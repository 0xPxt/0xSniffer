#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFSIZE SSIZE_MAX

int main(int argc, char *argv[]) {
    int pipeFileDescriptor;
    char chBuf[BUFSIZE] = {' '};
    int bytesRead = 0;

    if (argc != 2) {
        exit(1);
    }

    pipeFileDescriptor = atoi(argv[1]);

    for(;;) { 
        // Read from standard input and stop on error or no data.
        bytesRead = read(pipeFileDescriptor, chBuf, BUFSIZE);
      
        if (bytesRead < 0) {
            break;
        }
 
        printf("%s\n", chBuf);
    }
}