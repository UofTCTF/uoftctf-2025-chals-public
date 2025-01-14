#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int setup(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
}

int vuln(){
    char c[1];
    read(0, c, 0x100);
    printf(c);
}

int main(){
    setup();
    vuln();
}