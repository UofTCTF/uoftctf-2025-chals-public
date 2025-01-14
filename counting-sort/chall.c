#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int setup(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
}

int sort(){
    char c[256] = {0};
    unsigned char *p = c;
    char *buf = malloc(0x200);
    int n = read(0, buf, 0x200);
    for (int i = 0; i < n; i++)
    {
        p[buf[i]]++;
    }

    free(buf);
    
    for (int i = 0; i < 256; i++)
    {
        int num = *(p++);
        for (int j = 0; j < num; j++)
        {
            putchar(i);
        }
    }
}

int main(){
    setup();
    sort();
}