#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bstrlib.h>
#include <string.h>
#include <errno.h>

#define USE_ESTABLISHED 4
#define IP_TO_HOST 4
#define HOST_TO_IP 8
#define REQ_LEN 40
#define LOCAL_SERVER_PORT "22006"
#define PEEK_N 12
#define F_OFF -12

/* Amount of lines that have been wrote to the talk log */
static ssize_t temp_log_n=0;


void log_watcher(FILE *log, ssize_t size){
	static fpos_t log_curs_pos;
	char *buffer = (char*)calloc(1,size);

		if(temp_log_n > size){
			fgetpos(log, &log_curs_pos);
			fread(buffer, size, 1, log);
			fprintf(stdout, "%s\n", buffer);
		}
	free(buffer);
}

int64_t chg_sock_option(int64_t *sock, int option){

	int64_t err, pek=0;
	int64_t option_val=1;
		switch(option){
			case SO_REUSEADDR:{
							if((err = setsockopt(
									*sock,	//socket.
					   		   SOL_SOCKET,	//socket level.
							 SO_REUSEADDR,	//option name.
							  &option_val,
						sizeof option_val))== -1){
						fprintf(stderr, "<chg_sock_option>ERROR<%s\n", strerror(errno));
							}
			break;
			}
			case SO_KEEPALIVE:{
							if((err = setsockopt(
									*sock,	//socket.
					   		   SOL_SOCKET,	//socket level.
							 SO_KEEPALIVE,	//option name.
							  &option_val,
						sizeof option_val))== -1){
						fprintf(stderr, "<chg_sock_option>ERROR<%s\n", strerror(errno));
							}
			break;
			}
			case MSG_WAITALL:{
							if((err = setsockopt(
									*sock,	//socket.
					   		   SOL_SOCKET,	//socket level.
							  MSG_WAITALL,	//option name.
							  &option_val,
						sizeof option_val))== -1){
						fprintf(stderr, "<chg_sock_option>ERROR<%s\n", strerror(errno));
							}
			break;
			}
			case PEEK_N:{
					if((pek = recv(*sock, NULL, sizeof *sock, MSG_PEEK)) > 0)						
			break;
			}
			default:{
				fprintf(stdout, "Unknown socket option.\n");
				break;
			}
		}
if(pek > 0)
	return pek;
else
	return(0);
}

/* get from */
char * get_ip_str(const struct sockaddr *sa, char *from, size_t maxlen){
	//get from; from remote
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    from, maxlen);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    from, maxlen);
            break;
        default:
        	snprintf(from, maxlen, "Unknown");
            return NULL;
    }
    return from;
}

/* Get ip string from hostname string */
int hostname_to_ip_p(char *hostname, char *result_ip_str, short opt){

	struct addrinfo pre_addr_settings, *result_addrinfo, *ptr_addrinfo;
	int err=0;

    char result[INET6_ADDRSTRLEN];

	memset(&pre_addr_settings, 0, sizeof pre_addr_settings);
	pre_addr_settings.ai_family = AF_UNSPEC; //ip4 or ip6 
	pre_addr_settings.ai_socktype = SOCK_STREAM; // TCP or SCTP
	pre_addr_settings.ai_flags = AI_NUMERICSERV;

	if((err = getaddrinfo(hostname, NULL, &pre_addr_settings, &result_addrinfo))<0){
		fprintf(stderr,"<host to ip>ERROR< Resolving %s failed %s\n",hostname,
			gai_strerror(err));
		exit(EXIT_FAILURE);
	}

	for(ptr_addrinfo = result_addrinfo;
		ptr_addrinfo != NULL; 
		ptr_addrinfo = ptr_addrinfo->ai_next){

        void *addr;

        if(ptr_addrinfo->ai_family == AF_INET){
            struct sockaddr_in *ip4 = (struct sockaddr_in *)ptr_addrinfo->ai_addr;
            addr = &(ip4->sin_addr);
        }else{
            struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)ptr_addrinfo->ai_addr;
            addr = &(ip6->sin6_addr);
        }
        if(opt == HOST_TO_IP){
            inet_ntop(ptr_addrinfo->ai_family, addr, result, sizeof result);        
		  snprintf(result_ip_str, sizeof result, "%s", result);
        }
        if(opt == IP_TO_HOST){
          snprintf(result_ip_str, sizeof result, "%s",
          	inet_ntoa(*(struct in_addr *)addr));
        }
    }
	freeaddrinfo(result_addrinfo);
return(0);
}

/* Make one local socket and set to listening */
void spawn_local_socket(int64_t *server_socket_fd, char *port){

	int64_t err = 0;
	int64_t sockopt=1;
	struct addrinfo pre_addr_load;
	struct addrinfo *local_addrinfo;

	memset(&local_addrinfo, 0, sizeof local_addrinfo);
		pre_addr_load.ai_family = AF_UNSPEC;
		pre_addr_load.ai_socktype = SOCK_STREAM;
		pre_addr_load.ai_flags = AI_PASSIVE;
		pre_addr_load.ai_protocol = 0;

	if(( err = getaddrinfo(NULL, port, &pre_addr_load, &local_addrinfo))!=0){

		fprintf(stderr,"<local>ERROR< Local address init \
		failed: %s\n", gai_strerror(err));

		exit(EXIT_FAILURE);
	}

	*server_socket_fd = socket(
		local_addrinfo->ai_family,
		local_addrinfo->ai_socktype,
		local_addrinfo->ai_protocol);

	if(*server_socket_fd == -1){

		fprintf(stderr,"<local>ERROR< Socket creation \
		failed %d:%s\n", errno, strerror(errno));

		exit(EXIT_FAILURE);
	}

	if((err = chg_sock_option(server_socket_fd, SO_REUSEADDR)) != 0){

		fprintf(stderr,"<local>ERROR< Set socket option \
		failed %s\n", gai_strerror(err));

		exit(EXIT_FAILURE);	
	}

	if((err = bind(*server_socket_fd, 
		local_addrinfo->ai_addr, 
		local_addrinfo->ai_addrlen)<0)){

		fprintf(stderr,"<local>ERROR< The binding \
		failed %d:%s\n",errno, strerror(errno));

		exit(EXIT_FAILURE);
	}

	if((err = listen(*server_socket_fd, 5))<0){

		fprintf(stderr,"<local>ERROR< Listening \
		failed %d:%s\n",errno, strerror(errno));

		exit(EXIT_FAILURE);
	}

freeaddrinfo(local_addrinfo);
}

/* connect to remote host */
int 
connect_remote_socket(
	int64_t *connect_socket, char *host, char *port, unsigned short opt){

	*connect_socket=0;
	int err = 0;
	struct sockaddr_storage peer_addrinfo;
	char peer_ipaddr[INET6_ADDRSTRLEN];
	socklen_t len=0;

	char peer_hostname[NI_MAXHOST];
	char peer_servicename[NI_MAXSERV];
	int peer_port=0;

	struct addrinfo pre_addr_load; 
	struct addrinfo *remote_addrinfo;

	memset(&pre_addr_load, 0, sizeof pre_addr_load);
		pre_addr_load.ai_family = AF_UNSPEC;
		pre_addr_load.ai_socktype = SOCK_STREAM;
		pre_addr_load.ai_flags = AI_NUMERICSERV;

	switch(opt){
		//going to use this later
		case USE_ESTABLISHED : {

			if((err = getpeername(*connect_socket,
				(struct sockaddr *)&peer_addrinfo, &len))<0){

				fprintf(stderr, "<remote>ERROR< Failed to get peer address info %d:%s\n",
					errno, strerror(errno));

				exit(EXIT_FAILURE);
			}

			if(peer_addrinfo.ss_family == AF_INET){

				struct sockaddr_in *peer_use_parameters = 
				(struct sockaddr_in*)&peer_addrinfo;

				peer_port = ntohs(peer_use_parameters->sin_port);
				inet_ntop(AF_INET, &peer_use_parameters->sin_addr, peer_ipaddr,
				sizeof peer_ipaddr);

			} else {

				struct sockaddr_in6 *peer_use_parameters =
				(struct sockaddr_in6*)&peer_addrinfo;

				peer_port = ntohs(peer_use_parameters->sin6_port);
				
				inet_ntop(AF_INET6, &peer_use_parameters->sin6_addr, peer_ipaddr,
				sizeof peer_ipaddr);			 
			}/* now peer_ipaddr = remote address and peer_port = remote port */

			/* Now we get remote host name and service name */
			if((err = getnameinfo(
				(struct sockaddr*)&peer_addrinfo, sizeof peer_addrinfo, 
						peer_hostname, 
				 sizeof peer_hostname, 
				 	 peer_servicename, 
			  sizeof peer_servicename, 0))<0){

				fprintf(stderr, "<remote>ERROR< Peer host and service retreive \
				failed %s\n",gai_strerror(err));

				exit(EXIT_FAILURE);
			}

			if((err = connect(
				*connect_socket, (struct sockaddr *)&peer_addrinfo, len))<0){

				fprintf(stderr, "<remote>ERROR< Connecting to established remote \
				failed %d:%s\n",errno, strerror(errno));

				exit(EXIT_FAILURE);
			}
			break;
		}

		default:{
			if((err = getaddrinfo(host, port, &pre_addr_load, &remote_addrinfo))<0){

				fprintf(
					stderr, "<remote>ERROR< User defined connection parameters: \
					 <%s:%s> failed: %s\n",
					host, port, gai_strerror(err));

				exit(EXIT_FAILURE);
			}
			*connect_socket = socket(
					remote_addrinfo->ai_family, 
				  	remote_addrinfo->ai_socktype, 
				  	remote_addrinfo->ai_protocol);
			//connect
			if((err = connect(*connect_socket, 
					 remote_addrinfo->ai_addr, 
					 remote_addrinfo->ai_addrlen))<0){

				fprintf(stderr, "<remote>ERROR< Connecting to remote failed \
				 %d:%s\n",errno, strerror(errno));

				exit(EXIT_FAILURE);
			}			
		freeaddrinfo(remote_addrinfo);
		}
	}
return(0);
}

/* Retreive buffer from accepted socket and post to stdout */
ssize_t 
message_recv(int64_t *in_socket_fd, char *from, FILE *tmp_log, void *buff, size_t n){

	int err=0;
	char ch;
	char *buffer;
	ssize_t nchars_in;
	size_t nchars_total;

	if(n <= 0 || buff == NULL){
		errno = EINVAL;
		return -1;
	}

	buffer = (char *)buff;
	nchars_total = 0;

		for(;;){
			//log(n) ???
			nchars_in = read(*in_socket_fd, &ch, 1);

			if(nchars_in == -1){
				if(errno == EINTR)
					continue;
				else
					return -1;				
			} else if(nchars_in == 0){
				if(nchars_total == 0)
					return 0;
				else
					break;
			}else{
				if(nchars_total < n - 1){
					nchars_total++;
					*buffer++ = ch;
				}

				if(ch == '\n')
					break;
			}
		}
		//HUH?
		*buffer = '\0';
		
temp_log_n += fprintf(tmp_log,"[%s][%s][%s]: %s\n",__DATE__, __TIME__, from, buffer);
			
	if((err = fflush(tmp_log))==EOF){

		fprintf(stderr,"<get message>ERROR< failed to flush write on recv %d:%s\n",
			errno,strerror(errno));

		exit(EXIT_FAILURE);
	}
memset(&buffer, 0, sizeof buffer);
return nchars_total;
}

/* Retreive buffer from accepted socket and post to stdout */
ssize_t 
message_send(int64_t *out_socket_fd, const void *buff, size_t n, FILE *tmp_log){

	int err=0;
	const char *buffer;
	ssize_t nchars_out;
	ssize_t nchars_wrote;
	ssize_t line_size=0;
	size_t line_buffer_size = 40;
	size_t nchars_total;
	/* INPUT */
	int ch;
	char *p;
	char *line_buffer = (char*)calloc(1, line_buffer_size);
	char from[NI_MAXHOST];
	gethostname(from, sizeof(from));
/* Input strings */
fprintf(stdout, "(tab+enter to)send:\n");

	if((line_size = getline(&line_buffer, &line_buffer_size, stdin))== -1){

		fprintf(stderr, "<get message>ERROR< input error %d:%s\n",
			errno,strerror(errno));

		exit(EXIT_FAILURE);
	}else{
		p = strchr(line_buffer, '\n');
		if(p){
			*p = '\0';
		} else {
			while(((ch = getchar()) != '\t') && !feof(stdin) && !ferror(stdin));
		}
	}
/* Send message over connection. */
	buffer = (const char *)buff;
	buffer = line_buffer;

	for(nchars_total = 0; nchars_total < n;){

		nchars_out = write(*out_socket_fd, buffer, n - nchars_total);

		if(nchars_out <= 0){
			if((nchars_out == -1) && (errno == EINTR))
				continue;
			else
				return -1;
		}

		nchars_total += nchars_out;
		buffer += nchars_out;
	}

nchars_wrote = fprintf(tmp_log,"[%s][%s][%s]: %s\n",__DATE__, __TIME__, from, buffer);
temp_log_n += nchars_wrote;

	log_watcher(tmp_log, nchars_wrote);
			
	if((err = fflush(tmp_log))==EOF){

		fprintf(stderr,"<get message>ERROR< failed to flush write on recv %d:%s\n",
			errno,strerror(errno));

		exit(EXIT_FAILURE);
	}
memset(&buffer, 0, sizeof buffer);
return nchars_total;
}



int main(int argc, const char **argv){

	/* Temp log in /tmp with random name. */
	char log_template[] = "/tmp/cli_talk_logXXXXXX";
	int64_t talk_log;
	int err;

	 if((talk_log = mkstemp(log_template))<0){

	 	fprintf(
	 	stderr,"<logfile>ERROR< Failed to create temp file \
	 	%d:%s\n",errno,strerror(errno));

	 	exit(EXIT_FAILURE);
	 }
	 /* open log as file. */
	 FILE *temp_log;
	 if((temp_log = fopen(log_template,"r+a"))==NULL){

	 	fprintf(stderr,"<logfile>ERROR< failed to open talk log as FILE \
	 	%d:%s\n",errno,strerror(errno));

	 	exit(EXIT_FAILURE);
	 }
	 /* set log buffer to unbuffered */
	 if((err = setvbuf(temp_log,NULL,_IONBF,0))!=0){

	 	fprintf(stderr,"<logfile>ERROR< failed to set IO buffer \
	 	%d:%s\n",errno,strerror(errno));

	 	exit(EXIT_FAILURE);
	 }

	//server parameters
	int reqlen=0;
	char port[6]=LOCAL_SERVER_PORT;
	//connections fds (file descriptors)

	int64_t local_server_socket=0;
	int64_t remote_accepted_socket=F_OFF;
	int64_t connect_socket=F_OFF;

	/* strsep using these */
	char *connect_or_wait = NULL;
	char *connect_parameters = NULL;
	char *remote_host;
	char **remote_port = &connect_parameters;
	char request_str_len[REQ_LEN];
	char send_str_len[REQ_LEN];

	size_t len_conn_or_wait=0;
	size_t len_connect_parameters=0;
	ssize_t pek_size=0;
	//accepted
	char from[NI_MAXHOST]={0};
	//accepting 
	struct sockaddr_storage remote_address_parameters;
	socklen_t addr_size, sock_opt=1;
	addr_size = sizeof remote_address_parameters;
//start main server listening.
	spawn_local_socket(&local_server_socket, port);
//main loop for server
for(;;) {
	//while there is no connection			
		while((!connect_socket) || (!remote_accepted_socket)){

			do{
				/* ask where to connect or wait. */
				fprintf(stdout, "Make connection or wait? [y/N]");
				getline(&connect_or_wait, &len_conn_or_wait, stdin);
				/* Make connection. */
				if((strncmp(connect_or_wait,"y", 1)==0) || 
				   (strncmp(connect_or_wait,"yes", 3)==0) ||
				   (strncmp(connect_or_wait,"Y", 1)==0) ||
				   (strncmp(connect_or_wait,"Yes", 3)==0)){

					fprintf(stdout, "Where? [host:port]");

					getline(&connect_parameters, &len_connect_parameters, stdin);
						remote_host = strsep(remote_port,":");    
									  strsep(remote_port,"\n");

					connect_remote_socket(&connect_socket, remote_host, *remote_port, 0);

					free(connect_parameters);
					free(connect_or_wait);

				/* Were going to wait. */
				}else if((strncmp(connect_or_wait,"n", 1)==0) ||
						 (strncmp(connect_or_wait,"no", 2)==0) ||
						 (strncmp(connect_or_wait,"N", 1)==0) ||
						 (strncmp(connect_or_wait,"No", 2)==0)){

					fprintf(stdout, "\tWaiting for connection.\t");

				/* accept connection. */		
				remote_accepted_socket = accept(
					local_server_socket,(struct sockaddr *)&remote_address_parameters, 
					&addr_size);

				get_ip_str(
					(struct sockaddr *)&remote_address_parameters,from, NI_MAXHOST);

				fprintf(stdout, "Connection from: %s\n", from);
					
				}else if((remote_accepted_socket < 0) &&
						 (remote_accepted_socket != F_OFF)){

					fprintf(
						stderr,"<main loop:accept>ERROR< connection failed \
						 %d:%s\n",errno,strerror(errno));

						exit(EXIT_FAILURE);
				} else {

					fprintf(stdout, "\n...exiting...\n");

					exit(EXIT_SUCCESS);
				}
			}while((!connect_socket) || (!remote_accepted_socket));
		/* Jump back to main loop once we have a stream socket. */
		break;
		}
		/* Handle connection. */
		while((connect_socket != F_OFF) || (remote_accepted_socket != F_OFF)){
			/* Check if accepted connection has a message. */
			while(remote_accepted_socket != F_OFF){

				chg_sock_option(&remote_accepted_socket, MSG_WAITALL);

				if((pek_size = chg_sock_option(
					&remote_accepted_socket,PEEK_N)) > 0){

					message_recv(&remote_accepted_socket, 
											   	    from, 
										   	    temp_log, 
										 request_str_len, pek_size);
					log_watcher(temp_log, pek_size);
				break;
				}
			}
			
			/* Check if connected has a message. */
			while(connect_socket != F_OFF){

				chg_sock_option(&remote_accepted_socket, MSG_WAITALL);

				if((pek_size = chg_sock_option(
					&remote_accepted_socket,PEEK_N)) > 0){
					message_recv(&remote_accepted_socket, 
											   	    from, 
										   	    temp_log, 
										 request_str_len, pek_size);

					log_watcher(temp_log, pek_size);
				break;
				}
			}
			
			reqlen = atoi(request_str_len);

			if(reqlen <= 0){
				continue;
			}
			/* send on accepted connection if typing */
			while(remote_accepted_socket != F_OFF){
				if(!feof(stdin) && !ferror(stdin)){

					message_send(&remote_accepted_socket,
											send_str_len, 
											 	 REQ_LEN, temp_log);
				break;
				}
			}
			/* accepted send. */

			/* send on connection we made. */
			while(connect_socket != F_OFF){
				if(!feof(stdin) && !ferror(stdin)){

					message_send(&connect_socket,
									send_str_len, 
										 REQ_LEN, temp_log);
				break;
				}
			}
			/* connection send */
		continue;
		}
 break;
}

/* end of server loop, do clean up. */
if(temp_log > 0)
	fclose(temp_log);

	if(connect_socket > 0)
		close(connect_socket);

		if(remote_accepted_socket > 0)
			close(remote_accepted_socket);

			if(local_server_socket > 0)
				close(local_server_socket);

exit(EXIT_SUCCESS);
}


/* tmp log buff stream going to act right>? */