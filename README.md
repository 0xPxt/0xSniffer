# 0xSniffer
Network Sniffer 👃

Compiling Sniffer:
=====================================================================================
* [LINUX] `gcc src/sniffer/*.c src/sniffer/linux/*.c src/sniffer/IOHandler/*.c src/sniffer/IOHandler/linux/*.c -I include/ -o Sniffer -std=gnu17 -lpcap -lpthread`
* [WIN]   `gcc -g3 src\sniffer\*.c src\sniffer\win32\*.c src\sniffer\IOHandler\*.c src\sniffer\IOHandler\win32\*.c -I include -o out\Sniffer.exe -lwpcap -lPacket -lws2_32 -std=gnu17`
=====================================================================================

Compiling Logger:
=====================================================================================
* [LINUX] `gcc src/logger/linux/*.c -I include/ -o Logger -std=gnu17`
* [WIN]   `gcc -g3 src\logger\win32\*.c -I include -o out\Logger.exe -std=gnu17`
=====================================================================================
