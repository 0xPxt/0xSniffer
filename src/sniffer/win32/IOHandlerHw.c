
#include "IOHandler.h"

#include <windows.h>

#include "ErrorHandler.h"

HANDLE IOHandler_loggerStdInWr;

void IOHandler_CreateAndStartLogger(void) {
    SECURITY_ATTRIBUTES securityAttr;
    PROCESS_INFORMATION loggerProcessInfo;    
    STARTUPINFO startupInfo;
    BOOL result = false;
    HANDLE loggerStdInRd;

    // Set the bInheritHandle flag so pipe handles are inherited
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = true;
    securityAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDIN. 
 
    if (!CreatePipe(&loggerStdInRd, &IOHandler_loggerStdInWr, &securityAttr, 0)) 
        ErrorHandler_DisplayErrorAndExit("Stdin CreatePipe");

    // Ensure the write handle to the pipe for STDIN is not inherited. 
 
    if (!SetHandleInformation(IOHandler_loggerStdInWr, HANDLE_FLAG_INHERIT, 0))
        ErrorHandler_DisplayErrorAndExit("Stdin SetHandleInformation"); 

    // Prepare parameters for child process creation.

    // Set up members of the PROCESS_INFORMATION structure.

    ZeroMemory( &loggerProcessInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory( &startupInfo, sizeof(STARTUPINFO) );
    startupInfo.cb = sizeof(STARTUPINFO); 
    startupInfo.hStdError = NULL;
    startupInfo.hStdOutput = NULL;
    startupInfo.hStdInput = loggerStdInRd;
    startupInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 

    result = CreateProcess(NULL, 
        TEXT("Logger"),         // command line 
        NULL,                   // process security attributes 
        NULL,                   // primary thread security attributes 
        true,                   // handles are inherited 
        CREATE_NEW_CONSOLE,     // creation flags 
        NULL,                   // use parent's environment 
        NULL,                   // use parent's current directory 
        &startupInfo,           // STARTUPINFO pointer 
        &loggerProcessInfo);    // receives PROCESS_INFORMATION 

    // If an error occurs, exit the application. 
    if (result == false) {
        ErrorHandler_DisplayErrorAndExit("CreateProcess");
    }

    // Close handles to the child process and its primary thread.
    CloseHandle(loggerProcessInfo.hProcess);
    CloseHandle(loggerProcessInfo.hThread);

    // Close handles to the stdin pipe no longer needed by the child process.
    CloseHandle(loggerStdInRd);
}

void IOHandler_WriteToLogger(void *packet, unsigned long packetLength) {
    (void) WriteFile(IOHandler_loggerStdInWr, packet, packetLength, NULL, NULL);
}

void IOHandler_CleanUp() {
    CloseHandle(IOHandler_loggerStdInWr);
}