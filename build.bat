gcc -g3 src\sniffer\*.c src\sniffer\win32\*.c -I include -o Sniffer.exe -lwpcap -lPacket -lws2_32 -std=gnu17
gcc -g3 src\logger\win32\*.c -I include -o Logger.exe -std=gnu17
