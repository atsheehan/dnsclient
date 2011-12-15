#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include "query.h"
#include "dns.h"

#define RESPONSE_BUFFER_SIZE 1000

// numer of query attempts
unsigned int attempts = 0;

void *query_dns_server(void *request_buffer, int *packet_size, 
		       const char *server, int port, int timeout, int retries, 
		       char *error_message) {
  
  int sd, bytes_sent, bytes_received;
  char *response_buffer;
  struct sockaddr_in server_addr;
  struct sigaction handler;    // for alarm handling 
          
  /* Open a socket for sending UDP datagrams. */
  sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP); 
  if (sd < 0) {
    strncpy(error_message, "could not open socket", ERROR_BUFFER);
    return 0;
  }

  /* Setup the destination address for the packet. */
  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server);
  server_addr.sin_port	      = htons(port);

  /* Setup signal handler for alarm/timeout. */
  handler.sa_handler = handle_alarm;
  handler.sa_flags   = 0;

  if (sigfillset(&handler.sa_mask) < 0) {
    strncpy(error_message, "sigfillset() failed", ERROR_BUFFER);
    close(sd);
    return 0;
  }

  if (sigaction(SIGALRM, &handler, 0) < 0) {
    strncpy(error_message, "sigaction() failed for SIGALRM", ERROR_BUFFER);
    close(sd);
    return 0;
  }

  fcntl(sd,F_SETOWN, getpid());

  /* Allocate space to receive the response packet. */ 
  response_buffer = malloc(RESPONSE_BUFFER_SIZE);
  if (response_buffer == 0) {
    strncpy(error_message, "could not allocate memory for response", ERROR_BUFFER);
    close(sd);
    return 0;
  }

  /* Send the packet and verify that all of it was sent. */
  bytes_sent = sendto(sd, request_buffer, *packet_size, 0,
  		      (struct sockaddr *)&server_addr,
  		      sizeof(struct sockaddr_in));
  if (bytes_sent != *packet_size) {
    strncpy(error_message, "full request packet was not sent", ERROR_BUFFER);
    close(sd);
    free(response_buffer);
    return 0;
  }

  /* Start the timer and wait for the response from the server. */
  alarm(timeout);

  while ((bytes_received = recvfrom(sd, response_buffer, 
				    RESPONSE_BUFFER_SIZE - 1, 
				    0, 0, 0)) < 0) {

    /* Check if the timeout signal went off. */
    if (errno == EINTR) {
      if (attempts < retries) {
	/* If we still have more retries left, re-send the request 
	   packet and reset the timeout alarm. */
	bytes_sent = sendto(sd, request_buffer, *packet_size, 0,
			    (struct sockaddr *)&server_addr,
			    sizeof(struct sockaddr_in));
	if (bytes_sent != *packet_size) {
	  strncpy(error_message, "full request packet on retry " 
		  "was not sent", ERROR_BUFFER);
	  close(sd);
	  free(response_buffer);
	  return 0;
	}
	alarm(timeout);

      } else {
	/* Too many retry attempts, return early. */
	strncpy(error_message, "no response from server", ERROR_BUFFER);
	close(sd);
	free(response_buffer);
	return 0;
      }
    }
  }

  /* Received the response packet so we can disable the timeout. */
  alarm(0);

  /* Reset the packet size add a null terminator to the buffer. */
  *packet_size = bytes_received;
  response_buffer[bytes_received] = 0;
  close(sd);

  return response_buffer;
}

/* Interrupt handler for network timeouts. */
void handle_alarm(int time)
{
  attempts += 1;
}

void free_response_buffer(void *buffer) {
  free(buffer);
}
