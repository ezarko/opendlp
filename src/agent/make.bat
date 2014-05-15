del OpenDLP.exe unzip.o search.o whitelist.o recurse_dir_list.o init.o regex.o upload.o mod10.o read_config.o md5.o dirlisting.o OpenDLP.o
gcc -c OpenDLP.c
gcc -c dirlisting.c
gcc -c md5.c
gcc -c read_config.c
gcc -c mod10.c
gcc -c upload.c
gcc -c regex.c
gcc -c init.c
gcc -c recurse_dir_list.c
gcc -c whitelist.c
gcc -c search.c
gcc -c unzip.c
gcc unzip.o search.o whitelist.o recurse_dir_list.o init.o regex.o upload.o mod10.o read_config.o md5.o dirlisting.o OpenDLP.o -lpcre -lws2_32 -lcurl -LC:\MinGW\bin -o OpenDLP.exe
