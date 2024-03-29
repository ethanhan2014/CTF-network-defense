#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

char buffer[256] = "";
char filename[256] = "";


int main(int argc, char *argv[])
{
  setreuid(geteuid(), geteuid());
  setregid(getegid(), getegid());

  if (argv[1]) {
    snprintf(filename, 255, "/var/challenge/level6/%s", basename(argv[1]));
    printf("Checking filename %s\n", filename);
    if (access(filename, X_OK)) {
      fprintf(stderr, "You do not have the permission to execute this file\n");
      return 1;
    }
  }
  else {
    fprintf(stderr, "Please provide the program name. Currently available programs:\n");
    system("/bin/ls /var/challenge/level6");
    return 2;
  }

  if (argv[2]) {
    strcpy(buffer, argv[2]);
  }
  else {
    printf("Provide the parameter(s):\n");
    gets(buffer); 
  }
  printf("Executing filename %s\n", filename);

  execlp(filename, filename, buffer, (char *)0);

  return 0;
}
  
  
  
  
