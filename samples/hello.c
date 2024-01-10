// gcc -g -no-pie -O0 hello.c -o hello
#include <stdio.h>
int main(int argc, char const *argv[])
{
    if(argc % 2 == 0) {
        printf("hello homo\n");
    }else {
        printf("hello harmony\n");
    }
    return 0;
}
