#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>

extern void fencrypt(char* in_data, char* out_data, char* iv, int size);
extern void fdecrypt(char* in_data, char* out_data, char* iv, int size);

int setUpServer(int portno) {
   int sockfd, n;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   int i=0;
   
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket"); 
	  close(sockfd);
      exit(1);
   }
   
   server = gethostbyname("localhost");
   
   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
	  close(sockfd);
      exit(0);
   }
   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);
   
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
	  close(sockfd);
	  perror("ERROR connecting");
      exit(1);
   }
   
   return sockfd;
}


void doprocessing (int sock, int sockserver, char* iv) {
   int n, p;
   char buffer[16384];
   char outputbuffer[16384];
   bzero(buffer,16384);
   
   //read from client
   while((n = read(sock,buffer,16384)) > 0) {
		bzero(outputbuffer,16384);
		fdecrypt(buffer, outputbuffer, iv, n);

	   // wrtiting to the actual server
	   p = write(sockserver,outputbuffer,n);
	   if (p < 0) {
		  perror("ERROR writing to socket");
		  close(sock);
		  close(sockserver);
		  exit(1);
	   }
	   if(n < 16384) {
		   break;
	   }
   }

   bzero(buffer,16384);
   bzero(outputbuffer,16384);
   // reading from actual server
   while((p = read(sockserver,buffer,16384)) > 0) {
	   fencrypt(buffer, outputbuffer, iv, p);
	   
	   // write to the client
	   n = write(sock,outputbuffer,p);
	   if (n <= 0) {
		  perror("ERROR writing to socket");
		  close(sock);
		  close(sockserver);
		  exit(1);
	   }
	   if(p < 16384) {
		   break;
	   }
   }
}

int servermain(char* key, char* reverse, char* host, char* port) {
   int sockfd, sockserver, newsockfd, portno, serverPort, clilen, val;
   char buffer[16384];
   struct sockaddr_in serv_addr, cli_addr;
   unsigned char iv[AES_BLOCK_SIZE];
   int n, pid;
   
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
	  close(sockfd);
	  exit(1);
   }
   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = atoi(reverse);
   serverPort = atoi(port);
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
	  close(sockfd);
	  exit(1);
   }
   
   listen(sockfd,100);
   clilen = sizeof(cli_addr);
   
   while (1) {
	  newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	  val = fcntl (sockfd, F_GETFL, 0); 
      fcntl (sockfd, F_SETFL, val | O_NONBLOCK);
	  
      if (newsockfd < 0) { 
         continue;
      }
      
      pid = fork();
    
      if (pid < 0) {
         perror("ERROR on fork");
		 close(sockfd);
	     close(newsockfd);
         exit(1);
      }
      
      if (pid == 0) {
         close(sockfd);

         bzero(iv,AES_BLOCK_SIZE);
         n = read(newsockfd,iv,AES_BLOCK_SIZE);
         sockserver=setUpServer(serverPort);
		 
		 val = fcntl (newsockfd, F_GETFL, 0); 
		 fcntl (newsockfd, F_SETFL, val | O_NONBLOCK);
		 val = fcntl (sockserver, F_GETFL, 0); 
		 fcntl (sockserver, F_SETFL, val | O_NONBLOCK);
		 
		 while(1){
			doprocessing(newsockfd, sockserver, iv);
         }
         close(newsockfd);
		 close(sockserver);
      }
      else {
         close(newsockfd);
      }
    
   }
   close(sockfd);
}


int clientmain(char* key, char* host, char* port) {
   int sockfd, portno, n, val;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   unsigned char iv[AES_BLOCK_SIZE];
   int i=0,c;
   
   char buffer[16384];
   char outputbuffer[16384];
  
   portno = atoi(port);
   
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
	  close(sockfd);
	  exit(1);
   }
  
   server = gethostbyname(host);
   
   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
	  close(sockfd);
      exit(0);
   }
   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);
   
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR connecting");
	  close(sockfd);
      exit(1);
   }

   fcntl (sockfd, F_SETFL, O_NONBLOCK);
   
   bzero(iv,AES_BLOCK_SIZE);
   if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Could not create random bytes.");
		close(sockfd);
        exit(1);    
    }

   n = write(sockfd, iv, AES_BLOCK_SIZE);
   if (n <= 0) {
      perror("ERROR writing to socket");
	  close(sockfd);
      exit(1);
   }
   
   // make STDIN non-blocking
   fcntl (0, F_SETFL, O_NONBLOCK);
   fcntl (1, F_SETFL, O_NONBLOCK);
   
   while(1){
      bzero(buffer, 16384); 
      bzero(outputbuffer, 16384);
	  while((c=read(0, buffer, 16384)) > 0){
		  fencrypt(buffer, outputbuffer, iv, c);

		  n = write(sockfd, outputbuffer, c);
		  if (n <= 0) {
			 perror("ERROR writing to socket");
			 close(sockfd);
			 exit(1);
		  }
		  if(c < 16384) {
			  break;
		  }
	  }
      bzero(buffer, 16384);
	  bzero(outputbuffer,16384);
	  while((n = read(sockfd, buffer, 16384)) > 0) {
		fdecrypt(buffer, outputbuffer, iv, n);
		c=write(1, outputbuffer, n);
		if(n < 16384) {
			break;
		}
      }
   }
   return 0;
}


int main(int argc, char **argv){
        int c;
        char* key=NULL;
        char* reverse=NULL;
        char* host=NULL;
        char* port=0;
        
		// parsing command line argument to the user level variables
        while ((c = getopt(argc, argv, "k:l:h:p:")) != -1){
                switch(c){
                // key
                case 'k':
                     key=optarg;
                     break;
                // reverse proxy
                case 'l':
                     reverse=optarg;
                     break;
                default:
                      break;
                }
        }

        host = argv[optind];
        port = argv[optind+1];

        /*if (argc > 9) {
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                exit(EXIT_FAILURE);
        }*/

        if(reverse == NULL){
				clientmain(key, host, port);
        }
        else{
				servermain(key, reverse, host, port);
        }
  return 0;
}
