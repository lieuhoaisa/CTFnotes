#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *fp;
    char *buf = malloc(100);
    char msg[100];
    
    memset(msg, 0, 100);  
    fp = fopen("key.txt", "rw");
    fp->_flags &= ~4;
    fp->_IO_buf_base = msg;
    fp->_IO_buf_end = msg + 100;
    fp->_fileno = 0;

    fread(buf, 1, 6, fp);  
    puts(msg); 

    return 0;
}
