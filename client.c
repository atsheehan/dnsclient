#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h> 
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dns.h"
#include "request.h"
#include "response.h"
#include "query.h"

#define DEFAULT_PORT		53
#define DEFAULT_TIMEOUT		5
#define DEFAULT_MAX_RETRIES	3
#define MAX_IP_STRING_SIZE	16

static void format_ip_address(uint32_t ip_address, char *buffer);
static char *get_authority_string(int is_authoritative);

int main(int argc, char **argv) {

  char server[MAX_DOMAIN_LENGTH + 1], domain[MAX_DOMAIN_LENGTH + 1];
  char error_message[ERROR_BUFFER + 1], ip_buffer[MAX_IP_STRING_SIZE];
  int i, request_id, packet_size, answer_count;
  int port, timeout, retries, arg_counter, optional_argc, request_q_type;
  void *request_buffer, *response_buffer;
  struct dns_response *responses;

  *error_message = 0;

  /* Use the current time as a seed for the random number generator. */
  srand(time(0));

  /* Verify that enough arguments were passed in */
  if (argc <  3) {
    printf("USAGE: %s [-p <port>] [-t <timeout>] [-i <max-retries>] "
	   "[-ns|-mx] @<server> <name>\n", argv[0]);
    exit(1);
  }

  /* set defaults for optional arguments in case none are specified */
  port		 = DEFAULT_PORT;
  timeout	 = DEFAULT_TIMEOUT;
  retries	 = DEFAULT_MAX_RETRIES;
  request_q_type = DNS_A_RECORD;

  // counter that will be used to differntiate
  // vals from option flags
  optional_argc = argc - 2;
  arg_counter	= 1;

  // while we have enough args and the count is less
  // than the number of REQUIRED args 
  while(arg_counter < optional_argc) {
        
    // handle timeout arg
    if (strcmp("-t", argv[arg_counter]) == 0) {
      if (arg_counter + 1 < optional_argc) {
	timeout = atoi(argv[++arg_counter]);
      } else {
	fprintf(stderr, "ERROR must specify a timeout value with -t\n");
	exit(1);
      }

      // handle max retries arg
    } else if (strcmp("-i", argv[arg_counter]) == 0) {
      if (arg_counter + 1 < optional_argc) {
	retries = atoi(argv[++arg_counter]);
      } else {
	fprintf(stderr, "ERROR must specify a retry value with -i\n");
	exit(1);
      }

      // handle port arg
    } else if (strcmp("-p", argv[arg_counter]) == 0) {
      if (arg_counter + 1 < optional_argc) {
	port = atoi(argv[++arg_counter]);
      } else {
	fprintf(stderr, "ERROR must specify a port with -p\n");
	exit(1);
      }

    } else if (strcmp("-ns",argv[arg_counter]) == 0) {
      request_q_type = DNS_NS_RECORD;

    } else if (strcmp("-mx",argv[arg_counter]) == 0) {
      request_q_type = DNS_MX_RECORD;
    }

    ++arg_counter;
  }

  if (strlen(argv[argc - 2]) > MAX_DOMAIN_LENGTH ||
      strlen(argv[argc - 1]) > MAX_DOMAIN_LENGTH) {
    fprintf(stderr, "ERROR max length of server and domain is %d\n", 
	    MAX_DOMAIN_LENGTH);
    exit(1);
  }

  /* Use arg list to set REQUIRED variables. If the server name starts with an
     @, don't include it when copying into the buffer. */
  if (*argv[argc - 2] == '@') {
    strncpy(server, argv[argc - 2] + 1, MAX_DOMAIN_LENGTH);
  } else {
    strncpy(server, argv[argc - 2], MAX_DOMAIN_LENGTH);
  }
  strncpy(domain, argv[argc - 1], MAX_DOMAIN_LENGTH);


  /* Build the DNS request packet for the supplied domain name. */
  request_buffer = build_dns_request_packet(domain, &packet_size, &request_id, 
					    request_q_type, error_message);
  if (request_buffer == 0) {
    fprintf(stderr, "ERROR %s\n", error_message);
    exit(1);
  }

  /* Send the request packet and wait for a response from the server. */
  response_buffer = query_dns_server(request_buffer, &packet_size, server, 
				     port, timeout, retries, error_message);
  free_dns_request_packet(request_buffer);
  if (response_buffer == 0) {
    fprintf(stderr, "ERROR %s\n", error_message);
    exit(1);
  }

  /* Parse the response from the server. */
  responses = parse_dns_response(response_buffer, packet_size, request_id, 
				 domain, &answer_count, error_message);
  free_response_buffer(response_buffer);

  /* If a null value was returned, it could either mean there was an error or
     the domain name was not found. Check the error_message buffer to see
     if it contains any data. */
  if (responses == 0) {
    if (*error_message != 0) {
      fprintf(stderr, "ERROR %s\n", error_message);
      exit(1);
    } else {
      fprintf(stdout, "NOTFOUND\n");
      exit(0);
    }
  }

  for (i = 0; i < answer_count; ++i) {
    switch(responses[i].response_type) {
    case DNS_A_RECORD:
      format_ip_address(responses[i].ip_address, ip_buffer);
      fprintf(stdout, "IP\t%s\t%d\t%s\n", ip_buffer, 
	      responses[i].cache_time, get_authority_string(responses[i].authoritative));
      break;

    case DNS_NS_RECORD:
      fprintf(stdout, "NS\t%s\t%d\t%s\n", responses[i].name, 
	      responses[i].cache_time, get_authority_string(responses[i].authoritative));
      break;

    case DNS_CNAME_RECORD:
      fprintf(stdout, "CNAME\t%s\t%d\t%s\n", responses[i].name, 
	      responses[i].cache_time, get_authority_string(responses[i].authoritative));
      break;

    case DNS_MX_RECORD:
      fprintf(stdout, "MX\t%s\t%d\t%d\t%s\n", responses[i].name, 
	      responses[i].preference, responses[i].cache_time, 
	      get_authority_string(responses[i].authoritative));
      break;

    default:
      fprintf(stderr, "ERROR unknown response type\n");
      break;
    }
  }

  free(responses);
  return 0;
}

/* Formats a 32-bit IP address into a dotted quad string and
   copies it into the given buffer. */
static void format_ip_address(uint32_t ip_address, char *buffer) {
  uint8_t *segments = (uint8_t *)&ip_address;

  sprintf(buffer, "%d.%d.%d.%d", segments[3], segments[2],
  	  segments[1], segments[0]);
}

static char *get_authority_string(int is_authoritative) {
  return is_authoritative ? "auth" : "nonauth";
}
