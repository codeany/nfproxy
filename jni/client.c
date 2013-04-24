#include "unp.h"

void str_cli(FILE *fd, int sockfd);

int main(int argc, char **argv)
{
  int sockfd;
  struct sockaddr_in servaddr;
  
  if (argc != 2) {
    printf("usage: client <IPaddress>");
    exit(1);
  };
  
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
  memset(&servaddr, '\0', sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(80);
  inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
  
  if (-1 == connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr))) {
    printf("connect failed, errno %d", errno);
    exit(1);
  }
  str_cli(stdin, sockfd);
  
  exit(0);
}

void str_cli(FILE *fp, int sockfd)
{
  int    maxfd, stdineof;
  fd_set rset;
  char   buf[MAXLINE];
  int    n;
  
  stdineof = 0;
  FD_ZERO(&rset);
  
  for (;;) {
    if (stdineof == 0)
      FD_SET(fileno(fp), &rset);
    FD_SET(sockfd, &rset);
    maxfd = max(fileno(fp), sockfd);
    
    select(maxfd + 1, &rset, NULL, NULL, NULL);
    
    if (FD_ISSET(sockfd, &rset)) {
      if ((n = read(sockfd, buf, MAXLINE)) == 0) {
        if (stdineof == 1)
          return;
        else {
          printf("str_cli: server terminated");
          exit(1);
        }
      }
      write(fileno(stdout), buf, n);
    }
    
    if (FD_ISSET(fileno(fp), &rset)) {
      if ((n = read(fileno(fp), buf, MAXLINE)) == 0) {
        stdineof = 1;
        shutdown(sockfd, SHUT_WR);
        FD_CLR(fileno(fp), &rset);
        continue;
      }
      
      write(sockfd, buf, n);
    }
  }
}
