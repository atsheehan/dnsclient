dnsclient: client.c request.c response.c query.c
	gcc -o dnsclient -Wall client.c request.c response.c query.c

