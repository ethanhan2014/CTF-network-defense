#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


#define BUFSIZE 512

int main(int argc, char *argv[]) {
  struct stat buf;
  char cmd[BUFSIZE];
  FILE *f = NULL;

  if (argv[1] == NULL) {
    fprintf(stderr, "Please provide an argument\n");
    exit(1);
  }
  
  if (stat(argv[1], &buf)) {
    fprintf(stderr, "Can't stat the file\n");
    exit(1);
  }
    
  if (buf.st_gid != getegid()) {
    fprintf(stderr, "The file must be owned by group %d\n", getegid());
    exit(1);
  }

  setreuid(geteuid(), geteuid());
  setregid(getegid(), getegid());
  
  sleep(1);

  if ((f = fopen(argv[1], "r")) == NULL) {
    fprintf(stderr, "Cannot open command file\n");
    return 1;
  }  

  while (fgets(cmd, BUFSIZE, f)) {
    if ((cmd[0] == '\n') || (cmd[0] == 0x7f)) {
      fprintf(stderr, "Found empty line, quitting!\n");
      return 2;
    }
	
    system(cmd);
  }
  
  printf("Done!\n");
  return 0;
}

  
