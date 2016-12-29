/*
für IP_TRANSPARENT siehe https://www.kernel.org/doc/Documentation/networking/tproxy.txt
 iptables -t mangle -N DIVERT
 iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
 iptables -t mangle -A DIVERT -j MARK --set-mark 1
 iptables -t mangle -A DIVERT -j ACCEPT
 ip rule add fwmark 1 lookup 100
 ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -p tcp --dport 554 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 5540
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BACKLOG 10
#define PROXYPORT 5540
#define IP_TRANSPARENT 19
#define BUFFER 2000

char orig_dst_str[INET_ADDRSTRLEN]; //Originale Ziel IP

int get_org_dstaddr(int sockfd, struct sockaddr_storage *orig_dst);
char * stringReplace(char *search, char *replace, char *string);

int main(int argc , char *argv[])
{
  int socket_desc, new_socket, c, i, proxysocket;
  struct sockaddr_in server, client, proxyclient;
  struct sockaddr_storage orig_dst;
  char message[BUFFER];
  char oldip[] = "10.1.1.32"; // zu ersetzende interne IP
  char newip[] = "109.205.200.75"; // öffentliche IP

  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1)
  {
    perror("Socket: ");
    exit(EXIT_FAILURE);
  }

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(PROXYPORT);

  if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &server, sizeof(server)) == -1)
  {
    perror("setsockopt (SO_REUSEADDR): ");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  // IP_TRANSPARENT setzen, damit auch connections zu nicht lokalen IP adressen akzeptiert werden
  if (setsockopt(socket_desc, SOL_IP, IP_TRANSPARENT, &server, sizeof(server)) == -1)
  {
    perror("setsockopt (IP_TRANSPARENT): ");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
  {
    perror("bind failed: ");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  listen(socket_desc, 3);

  printf("Listen on Port: %i\r\n", PROXYPORT);

  c = sizeof(struct sockaddr_in);
  while((new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))) // Verbindung akzeptieren
  {
    //original ip auslesen
    get_org_dstaddr(new_socket, &orig_dst);
    printf("Connection accepted to destination: %s\r\n", orig_dst_str);
    // socket für connection zu original ziel
    proxysocket = socket(AF_INET , SOCK_STREAM , 0);
    if (proxysocket == -1)
    {
      perror("Proxy Client Socket: ");
      exit(EXIT_FAILURE);
    }
    proxyclient.sin_addr.s_addr = inet_addr(orig_dst_str);
    proxyclient.sin_family = AF_INET;
    proxyclient.sin_port = htons(554);
    // zu original ziel connecten
    if(connect(proxysocket, (struct sockaddr *)&proxyclient, sizeof(proxyclient)))
    {
      perror("connect failed: "); exit(EXIT_FAILURE);
    }
    printf("Connected to: %s\r\n", orig_dst_str);

    message[0] = '\0';

    fd_set read_set;
    struct timeval timeout;

    timeout.tv_sec = 15; // Timeout after 15s
    timeout.tv_usec = 0;

    FD_ZERO(&read_set);
    FD_SET(new_socket, &read_set);

    int r=select(new_socket+1, &read_set, NULL, NULL, &timeout);

    if( r<0 )
    {
      puts("fehler");
      exit(EXIT_FAILURE);
    }

    if( r==0 )
    {
        // Timeout
        puts("timeout");
    }

    if( r>0 )
    {
      // ready zum lesen
      while(i = recv(new_socket, message, sizeof(message),0)) //empfangen
      {
        puts("get message:");

        message[i] = '\0';
        puts(message);

        stringReplace(oldip, newip, message); // interne durch öffentliche ip ersetzen

        if(send(proxysocket, message, strlen(message), 0) < 0) //zum orignal ziel senden
        {
          puts("fehler");
        }
        message[0] = '\0';

        recv(proxysocket, message, sizeof(message),0); //antwort vom ziel empfangen

        printf("Send message: \r\n%s\r\n", message);

        if(send(new_socket, message, strlen(message), 0) < 0) //zur tv box zurück senden
        {
          puts("fehler");
        }
      }
    }
  }

  close(proxysocket);
  close(new_socket);
  return 0;
}


int get_org_dstaddr(int sockfd, struct sockaddr_storage *orig_dst)
{
    socklen_t addrlen = sizeof(*orig_dst);
    memset(orig_dst, 0, addrlen);

    //For UDP transparent proxying:
    //Set IP_RECVORIGDSTADDR socket option for getting the original
    //destination of a datagram

    //Socket is bound to original destination
    if(getsockname(sockfd, (struct sockaddr*) orig_dst, &addrlen) < 0)
    {
        perror("getsockname: ");
        exit(EXIT_FAILURE);
    }
    else
    {
      if(orig_dst->ss_family == AF_INET)
      {
        inet_ntop(AF_INET, &(((struct sockaddr_in*) orig_dst)->sin_addr), orig_dst_str, INET_ADDRSTRLEN);
      }
    }
    return 0;
}

char * stringReplace(char *search, char *replace, char *string)
{
  char *tempString, *searchStart;
  int len=0;
  // preuefe ob Such-String vorhanden ist
  searchStart = strstr(string, search);

  if(searchStart == NULL)
  {
    return string;
  }

  // Speicher reservieren
  tempString = (char*) malloc(strlen(string) * sizeof(char));
  if(tempString == NULL)
  {
    return NULL;
  }

  // temporaere Kopie anlegen
  strcpy(tempString, string);

  // ersten Abschnitt in String setzen
  len = searchStart - string;
  string[len] = '\0';

  // zweiten Abschnitt anhaengen
  strcat(string, replace);

  // dritten Abschnitt anhaengen
  len += strlen(search);
  strcat(string, (char*)tempString+len);

  // Speicher freigeben
  free(tempString);

  return string;
}
