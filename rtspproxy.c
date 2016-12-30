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
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#define BANNER "RTSPProxy Daemon 0.2 alpha1"
#define BACKLOG 10
#define PROXYPORT 5540
#define IP_TRANSPARENT 19
#define BUFFER 2000

char orig_dst_str[INET_ADDRSTRLEN]; //Originale Ziel IP
typedef void (*sighandler_t)(int);
int debug = 0;

int get_org_dstaddr(int sockfd, struct sockaddr_storage *orig_dst);
char * stringReplace(char *search, char *replace, char *string);
static sighandler_t handle_signal(int sig_nr, sighandler_t signalhandler);
static void start_daemon(const char *log_name, int facility);

int main(int argc , char *argv[])
{
  int socket_desc, new_socket, c, i, proxysocket;
  struct sockaddr_in server, client, proxyclient;
  struct sockaddr_storage orig_dst;
  char message[BUFFER];
  char *teardown;
  char oldip[] = "10.1.1.32"; // zu ersetzende interne IP
  char newip[] = "109.205.200.75"; // öffentliche IP

  start_daemon("RTSPProxy", LOG_LOCAL0);

  syslog(LOG_NOTICE, "%s started (written by Stefan Mueller)", BANNER);

  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1)
  {
    syslog(LOG_ERR, "Socket failure");
    exit(EXIT_FAILURE);
  }

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(PROXYPORT);

  if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &server, sizeof(server)) == -1)
  {
    syslog(LOG_ERR, "setsockopt (SO_REUSEADDR)");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  // IP_TRANSPARENT setzen, damit auch connections zu nicht lokalen IP adressen akzeptiert werden
  if (setsockopt(socket_desc, SOL_IP, IP_TRANSPARENT, &server, sizeof(server)) == -1)
  {
    syslog(LOG_ERR, "setsockopt (IP_TRANSPARENT)");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
  {
    syslog(LOG_ERR, "Bind failed");
    close(socket_desc);
    exit(EXIT_FAILURE);
  }

  listen(socket_desc, 3);
  syslog(LOG_NOTICE,"Listen on Port %i",PROXYPORT);

  c = sizeof(struct sockaddr_in);
  while((new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))) // Verbindung akzeptieren
  {
    //original ip auslesen
    get_org_dstaddr(new_socket, &orig_dst);
    syslog(LOG_NOTICE, "Connection accepted to destination %s", orig_dst_str);
    // socket für connection zu original ziel
    proxysocket = socket(AF_INET , SOCK_STREAM , 0);
    if (proxysocket == -1)
    {
      syslog(LOG_ERR, "proxysocket error");
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
      //ERROR
      exit(EXIT_FAILURE);
    }

    if( r==0 )
    {
        // Timeout
    }

    if( r>0 )
    {
      // ready zum lesen
      while(i = recv(new_socket, message, sizeof(message),0)) //empfangen
      {
        if (i==0)
        {
          close(proxysocket);
          break;
        }

        teardown = strstr(message,"TEARDOWN");
        message[i] = '\0';
        stringReplace(oldip, newip, message); // interne durch öffentliche ip ersetzen

        if(send(proxysocket, message, strlen(message), 0) < 0) //zum orignal ziel senden
        {
          close(proxysocket); break;
        }

        message[0] = '\0';

        if (recv(proxysocket, message, sizeof(message),0) < 0) //antwort vom ziel empfangen
        {
          close(proxysocket);
          break;
        }

        if(send(new_socket, message, strlen(message), 0) < 0) //zur tv box zurück senden
        {
          close(proxysocket); break;
        }

        message[0] = '\0';
        if(teardown != NULL)
        {
          syslog(LOG_NOTICE, "teardown");
          break;
        }
        teardown = NULL;
      }
    }

  close(proxysocket);
  }

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
    closelog();
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

static sighandler_t handle_signal(int sig_nr, sighandler_t signalhandler)
{
  struct sigaction neu_sig, alt_sig;
  neu_sig.sa_handler = signalhandler;
  sigemptyset(&neu_sig.sa_mask);
  neu_sig.sa_flags = SA_RESTART;
  if (sigaction(sig_nr, &neu_sig, &alt_sig) < 0)
  {
    return SIG_ERR;
  }
  return alt_sig.sa_handler;
}

static void start_daemon(const char *log_name, int facility)
{
  int i;
  pid_t pid;

  if ((pid = fork()) != 0)
  {
    exit(EXIT_FAILURE);
  }

  if (setsid() < 0)
  {
    printf("%s kann nicht Sessionführer werden!\n", log_name);
    exit(EXIT_FAILURE);
  }

  handle_signal(SIGHUP, SIG_IGN);

  if ((pid = fork()) != 0)
  {
    exit(EXIT_FAILURE);
  }

  chdir("/");

  // bitmakse auf 0, damit init sich dem kindprozess annimmt
  umask(0);
  // schliessen aller fd's
  for (i = sysconf(_SC_OPEN_MAX); i > 0; i--)
  {
    close(i);
  }
  openlog(log_name, LOG_PID | LOG_CONS | LOG_NDELAY, facility);
}
