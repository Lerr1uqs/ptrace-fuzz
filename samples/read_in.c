// gcc -g -no-pie -O0 read_in.c -o read_in
#include <stdio.h>
#include <unistd.h>
#include<stdlib.h>
int main(int argc, char const *argv[])
{
    char buf[0x8];
    // buf[read(0, buf, 0x12)] = '\x00';
    read(0, buf, 0x100);
    buf[0x8] = '\0';
    // gets(buf);
    printf("read : %s\n", buf);
    return 0;
}
