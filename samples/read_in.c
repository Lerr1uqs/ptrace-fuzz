// gcc -g -no-pie -O0 read_in.c -o read_in
#include <stdio.h>
#include <unistd.h>
int main(int argc, char const *argv[])
{
    char buf[0x11];
    buf[read(0, buf, 0x10)] = '\x00';
    printf("read : %s\n", buf);
    return 0;
}
