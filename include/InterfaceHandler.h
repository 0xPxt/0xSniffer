#ifndef INTERFACE_HANDLER
#define INTERFACE_HANDLER

#include <pcap.h>

typedef enum InterfaceHandler_status {
    InterfaceHandler_status_OK = 0,
    InterfaceHandler_status_ERROR = -1
} InterfaceHandler_status_t;

extern void InterfaceHandler_Init(void);

extern InterfaceHandler_status_t InterfaceHandler_SelectInterface(int interfaceNumber);

extern InterfaceHandler_status_t InterfaceHandler_OpenCapture(void);

extern void InterfaceHandler_CapturePackets(void);

extern void InterfaceHandler_StopCapturing(void);

extern void InterfaceHandler_PrintInterfaces(void);

extern InterfaceHandler_status_t InterfaceHandler_PrintSelectedInterfaceInfo(void);

extern void InterfaceHandler_CleanUp(void);

#endif // INTERFACE_HANDLER
