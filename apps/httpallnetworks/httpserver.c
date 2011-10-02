#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include "lwip/opt.h"
#include "lwip/arch.h"
#include "lwip/api.h"
#include "lwip/tcp.h"

#include "httpserver.h"

#if LWIP_NETCONN

#ifndef HTTPD_DEBUG
#define HTTPD_DEBUG         LWIP_DBG_ON
#endif

const static char http_html_hdr[] = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\n\r\n";
const static char http_index_html[] = "<html><head><title>Congrats!</title></head><body><h1>Welcome to our lwIP HTTP server!</h1><p>This is a small test page, served by httpserver-netconn.</body></html>";

#define BUFSIZE 8096

#define ASE_PORT 9092

/** Serve one HTTP connection accepted in the http thread */
static void
http_server_netconn_serve(struct netconn *conn)
{
  struct netbuf *inbuf;
  char *buf;
  u16_t buflen;
  err_t err;
  char buffer[BUFSIZE + 1];
  int ret, bytes_sent;
  int file_fd = -1;
  int ase_sock = -1;
  int x;

  struct sockaddr_in ase_addr;
  char ase_buffer[BUFSIZE + 1];
  
  /* Read the data from the port, blocking if nothing yet there. 
   We assume the request (the part we care about) is in one netbuf */
  err = netconn_recv(conn, &inbuf);
  
  if (err == ERR_OK) {
    netbuf_data(inbuf, (void**)&buf, &buflen);
    
    /* Is this an HTTP GET command? (only check the first 5 chars, since
    there are other formats for GET, and we're keeping it very simple )*/
    if (buflen>=5 &&
        buf[0]=='G' &&
        buf[1]=='E' &&
        buf[2]=='T' &&
        buf[3]==' ' &&
        buf[4]=='/' ) {
      
      /* open the related file */
      if ((file_fd = open("testfile", O_RDONLY)) == -1){
	printf("cannot open file\n");
      }
      (void)sprintf(buffer,"HTTP/1.0 200 OK\r\nContent-Type: image/jpg\r\n\r\n");
      netconn_write(conn, buffer, strlen(buffer), NETCONN_COPY);

      /* open a hook so that this TCP connection can receive hints 
	 to enable/disable congestion control */
      ase_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      x=fcntl(ase_sock, F_GETFL,0);
      fcntl(ase_sock, F_SETFL, x | O_NONBLOCK);
      ase_addr.sin_family = AF_INET;
      ase_addr.sin_port = htons(ASE_PORT);
      ase_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      if (bind(ase_sock,&ase_addr,sizeof(ase_addr)) == -1){
	printf("error cannot bind ase server...\n");
	exit(1);
      }

      while(1){
	/* get data from file and send it to the client */
	ret = read(file_fd, buffer, BUFSIZE);
	if (ret > 0){
	  netconn_write_partly(conn, buffer, ret, NETCONN_COPY, &bytes_sent);
	}	  
	else{
	  break;
	}
	/* check if there is no command for ASE */
	ret = recv(ase_sock,ase_buffer, BUFSIZE,0);
	if (ret > 0){
	  if (tcp_congestion_control_enabled(conn->pcb.tcp)){
	    printf("Disabling congestion control\n");
	    tcp_congestion_control_disable(conn->pcb.tcp);
	  }
	  else{
	    printf("Enabling congestion control\n");
	    tcp_congestion_control_enable(conn->pcb.tcp);
	  }
	}

      }

      printf("done with file (code : %d)\n", ret);
      close(file_fd);
      close(ase_sock);
      
    }
  }
  /* Close the connection (server closes in HTTP) */
  netconn_close(conn);
  
  /* Delete the buffer (netconn_recv gives us ownership,
   so we have to make sure to deallocate the buffer) */
  netbuf_delete(inbuf);
}

/** The main function, never returns! */
static void
http_server_netconn_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);
  
  /* Create a new TCP connection handle */
  conn = netconn_new(NETCONN_TCP);
  LWIP_ERROR("http_server: invalid conn", (conn != NULL), return;);
  
  /* Bind to port 8080 (HTTP) with default IP address */
  netconn_bind(conn, NULL, 8080);
  
  /* Put the connection into LISTEN state */
  netconn_listen(conn);
  
  do {
    err = netconn_accept(conn, &newconn);
    if (err == ERR_OK) {
      http_server_netconn_serve(newconn);
      netconn_delete(newconn);
    }
  } while(err == ERR_OK);
  LWIP_DEBUGF(HTTPD_DEBUG,
	      ("http_server_netconn_thread: netconn_accept received error %d, shutting down",
     err));
  netconn_close(conn);
  netconn_delete(conn);
}

/** Initialize the HTTP server (start its thread) */
void
my_http_server_netconn_init()
{
  sys_thread_new("http_server_netconn", http_server_netconn_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}

#endif /* LWIP_NETCONN*/
