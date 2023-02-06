#include <stdio.h>
#include <stdlib.h>
#if _WIN32
#include <windows.h>
#endif

#define BUFSIZE 4096

int main(void) {
    HANDLE hStdin;
    DWORD dwRead;
    BOOL bSuccess;
    CHAR chBuf[BUFSIZE];

    hStdin = GetStdHandle(STD_INPUT_HANDLE);

    if (hStdin == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    for(;;) { 
        // Read from standard input and stop on error or no data.
        bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL); 
      
        if (!bSuccess) {
            break;
        }
 
        printf("%s\n", chBuf);
    }

    return 0;
}