# 0xSniffer
Network Sniffer 👃

Compiling Sniffer:
=====================================================================================
* [LINUX] `gcc src/sniffer/*.c -I include/ -o out/Sniffer -std=gnu17 -lpcap`
* [WIN]   `gcc -g3 src\sniffer\*.c -I include -o out\Sniffer.exe -lwpcap -lPacket -lws2_32 -std=gnu17`
=====================================================================================

Compiling Logger:
=====================================================================================
* [LINUX] `gcc src/logger/linux/*.c -I include/ -o out/Logger -std=gnu17`
* [WIN]   `gcc -g3 src\logger\win32\*.c -I include -o out\Logger.exe -std=gnu17`
=====================================================================================
