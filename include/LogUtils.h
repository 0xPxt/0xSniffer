#ifndef LOG_UTILS
#define LOG_UTILS

#include <stdio.h>

extern void LogUtils_ClearScreen(void);

extern void LogUtils_DisplayBanner(void);

extern void LogUtils_RequestFileName(char *fileName);

void LogUtils_RequestPacketID(int *id);

#endif // LOG_UTILS