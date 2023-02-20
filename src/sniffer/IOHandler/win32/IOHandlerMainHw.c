
#include "IOHandlerMain.h"

#include <windows.h>

#include "ErrorHandler.h"

HANDLE IOHandler_loggerStdInWr;

void IOHandlerMain_CreateAndStartLogger() {
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
        ErrorHandler_DisplayErrorAndExit("[IOHandlerMain] Could not create the In read pipe for the logger.");

    // Ensure the write handle to the pipe for STDIN is not inherited. 
 
    if (!SetHandleInformation(IOHandler_loggerStdInWr, HANDLE_FLAG_INHERIT, 0))
        ErrorHandler_DisplayErrorAndExit("[IOHandlerMain] Could not set the pipe as STDIN for the logger."); 

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
        ErrorHandler_DisplayErrorAndExit("[IOHandlerMain] Could not create the process for the logger.");
    }

    // Close handles to the child process and its primary thread.
    
    if (CloseHandle(loggerProcessInfo.hProcess) == false) {
        ErrorHandler_DisplayWarning("[IOHandlerMain] Could not close the logger's process handle.");
    }

    if (CloseHandle(loggerProcessInfo.hThread) == false) {
        ErrorHandler_DisplayWarning("[IOHandlerMain] Could not close the logger's thread handle.");
    }

    // Close handles to the stdin pipe no longer needed by the child process.

    if (CloseHandle(loggerStdInRd) == false) {
        ErrorHandler_DisplayWarning("[IOHandlerMain] Could not close the logger's In Read pipe handle.");
    }
}

void IOHandlerMain_WriteToLogger(void *packet, unsigned long packetLength) {
    if (WriteFile(IOHandler_loggerStdInWr, packet, packetLength, NULL, NULL) == false) {
        ErrorHandler_DisplayWarning("[IOHandlerMain] Error sending a packet to the Logger.");
    }
}

void IOHandlerMain_CleanUp() {
    if (CloseHandle(IOHandler_loggerStdInWr) == false) {
        ErrorHandler_DisplayWarning("[IOHandlerMain] Could not close the logger's write handle.");
    }
}