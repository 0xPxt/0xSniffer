#ifndef ERROR_HANDLER
#define ERROR_HANDLER
#include <stdbool.h>

extern void ErrorHandler_DisplayPcapErrorAndExit(char *error_message, bool printErrBuff);

extern void ErrorHandler_DisplayErrorAndExit(char *error_message);

extern void ErrorHandler_DisplayWarning(char *warning_message);

extern char *ErrorHandler_GetPcapErrorBuffer(void);

extern void ErrorHandler_CleanExit(void);

#endif //ERROR_HANDLER
