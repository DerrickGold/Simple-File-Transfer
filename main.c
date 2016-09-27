#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <libgen.h>

#define TEST_PORT "13337"
#define BACK_LOG 10
#define DATA_BUFFER_LEN 4096

typedef size_t SendHeader;
#define HEADER_SIZE (sizeof(SendHeader))

typedef enum {
  SERVER_WAITING_CON = 0,
  SERVER_CLIENT_CON,
  SERVER_CLIENT_DISCON,
  SERVER_CLIENT_TRANSFER,
} ServerStates;

typedef enum {
  CLIENT_SEND_META = 0,
  CLIENT_META_SENT,
  CLIENT_SEND_FILE,
  CLIENT_FILE_SENT
} ClientStates;

typedef enum {
  FILETYPE_DIR = 0,
  FILETYPE_FILE,
} FileMetaDataType;


typedef struct FileMetaData {
  unsigned int pathLen;
  FileMetaDataType type;
  char *path;
  char *localPath;
} FileMetaData;

char *packUInt64(char *out, unsigned long long in) {
  *out++ = (unsigned long long) in >> 56;
  *out++ = (unsigned long long) in >> 48;
  *out++ = (unsigned long long) in >> 40;
  *out++ = (unsigned long long) in >> 32;
  *out++ = in >> 24;
  *out++ = in >> 16;
  *out++ = in >> 8;
  *out = in;
  return out;
}

char *unpackUInt64(unsigned long long *out, char *in) {
  *out = (unsigned long long)in[0] << 56 |
    (unsigned long long)in[1] << 48 |
    (unsigned long long)in[2] << 40 |
    (unsigned long long)in[3] << 32 |
    in[4] << 24 |
    in[5] << 16 |
    in[6] << 8 |
    in[7];

  return &in[7];
}


char *packUInt(char *out, unsigned int in) {
  *out++ = in >> 24;
  *out++ = in >> 16;
  *out++ = in >> 8;
  *out = in;
  return out;
}

char *unpackUInt(unsigned int *out, char *in) {
  *out = (unsigned int)in[0] << 24 |
    (unsigned int) in[1] << 16 |
    (unsigned int) in[2] << 8 |
    (unsigned int) in[3];

  return &in[3];
}

char *packSizeT(char *out, size_t in) {
  if (sizeof(size_t) == 8)
    return packUInt64(out, in);

  return packUInt(out, in);
}

char *unpackSizeT(size_t *out, char *in) {
if (sizeof(size_t) == 8)
  return unpackUInt64((unsigned long long *)out, in);

 return unpackUInt((unsigned int *)out, in);
}


int unpackSendHeader(char *data, SendHeader *header) {
  size_t size = 0;
  unpackSizeT(&size, data);
  *header = size;
  return 0;
}

unsigned int packSendHeader(char *out, SendHeader *header) {
  packSizeT(out, *header);
  return HEADER_SIZE;
}

size_t prependSendHeader(char **wrapped, char *inputData, unsigned int len) {
  SendHeader header = len;
  char *out = NULL;
  
  *wrapped = calloc(1, header + HEADER_SIZE);
  if (!*wrapped) {
    fprintf(stderr, "Error prepending send header!\n");
    return -1;
  }
  out = *wrapped;
  packSendHeader(out, &header);
  memcpy(out + HEADER_SIZE, inputData, len);
  return len + HEADER_SIZE;
}

int getHeader(int sockfd, SendHeader *header) {
  char headerBuf[HEADER_SIZE];
  int n = recv(sockfd, headerBuf, sizeof(headerBuf), 0);
  if (n == -1 || n == 0) return n;
  if (unpackSendHeader(headerBuf, header)) return -1;
  return 0;
}



char *packFileMetadata(FileMetaData *metaData, size_t *len) {
  printf("PACKING METADATA\n");
  size_t headerSize = sizeof(unsigned long) + sizeof(FileMetaDataType);
  *len = headerSize + metaData->pathLen;
  char *serialized = calloc(1, *len);
  char *pos = serialized;
  if (!serialized) {
    fprintf(stderr, "Error serializing file metadata\n");
    return NULL;
  }

  printf("Path Len: %d\n", metaData->pathLen);
  pos = packUInt(pos, metaData->pathLen) + 1;
  printf("Type: %d\n", (int) metaData->type);
  *pos++ = metaData->type;
  printf("Path: %s\n", metaData->path);
  strncpy(pos, metaData->path, metaData->pathLen);
  return serialized;
}

void unpackFileMetadata(FileMetaData *metaData, char *input) {
  printf("UNPACKING METADATA\n");
  input = unpackUInt(&metaData->pathLen, input) + 1;
  printf("Path Len: %d\n", metaData->pathLen);
  metaData->type = (FileMetaDataType)*input++;
  printf("Type: %d\n", (int) metaData->type);
  
  metaData->path = calloc(1, metaData->pathLen);
  if (!metaData->path) {
    fprintf(stderr, "Error unpacking file metadata, allocating filepath error\n");
    return;
  }
  strncpy(metaData->path, input, metaData->pathLen);
  printf("Path: %s\n", metaData->path);
}


char *makeFileData(FileMetaData *metaData, size_t *size) {
  size_t totalLen, metaLen;
  char *output = NULL, *packed = NULL, *pos = NULL;

  packed = packFileMetadata(metaData, &metaLen);
  if (!packed) return NULL;
  printf("PACKED: %s\n", packed);
  
  totalLen = prependSendHeader(&output, packed, metaLen);
  printf("HEADER: %s\n", output);
  free(packed);
  *size = totalLen;
  return output;
}

int sendPackedData(int sockfd, char *data, size_t len) {
  size_t total = 0, bytesLeft = len;
  int n = 0;
  while (total < len) {
    n = send(sockfd, data+total, bytesLeft, 0);
    if (n == -1) break;
    total += n;
    bytesLeft -= n;
  }
  return n==-1?-1:0;
}

int sendFile(int sockfd, const char *path) {
  SendHeader header;
  struct stat st;
  size_t fileSize;
  char headerBuf[HEADER_SIZE];

  //get file size
  stat(path, &st);
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("file error: ");
    return -1;
  }
  printf("Sending %lld bytes\n", st.st_size);
  //send header first
	fileSize = st.st_size;
  header = fileSize;
  packSendHeader(headerBuf, &header);
  send(sockfd, headerBuf, sizeof(headerBuf), 0); 

  size_t sent = 0, read = 0;
  int n = 0, b = 0;
  char buffer[DATA_BUFFER_LEN];
  
  while (sent < fileSize) {
    b = fread(buffer, 1, sizeof(buffer), f);
    if (!b) break;
    n = send(sockfd, buffer, b, 0);
    if (!n || n == -1) break;
    read += b;
    sent += b;
  }
  fclose(f);
  return 0;
}


int recvPacket(int sockfd, FileMetaData *m) {
  char tempBuffer[DATA_BUFFER_LEN];
  char *finalPacket = NULL, *writePos;
  size_t bytesLeft = 0;
  int n = 0;

  SendHeader header;
  if (getHeader(sockfd, &header)) {
    fprintf(stderr, "Error receiving send header\n");
    exit(1);
  }
  bytesLeft = (unsigned int)header;
  
  finalPacket = calloc(1, bytesLeft);
  if (!finalPacket) {
    fprintf(stderr, "Not enough memory to receive data!\n");
    exit(1);
  }
  writePos = finalPacket;
  while (bytesLeft > 0) {
    unsigned int readSize = (bytesLeft < DATA_BUFFER_LEN) ? bytesLeft : DATA_BUFFER_LEN;
    n = recv(sockfd, tempBuffer, readSize, 0);
    if (n == -1 || n == 0) break;
   
    memcpy(writePos, tempBuffer, n);
    bytesLeft -= n;
    writePos += n;
  }
  unpackFileMetadata(m, finalPacket);
  return 0;
}

int recvFile(int sockfd, FileMetaData *m) {
  char tempPath[strlen(m->path) + strlen("TEST")];
  sprintf(tempPath, "TEST%s", m->path);
  FILE *f = fopen(tempPath, "wb");
  if (!f) {
    perror("File open: ");
    return -1;
  }
  int n = -1;
  char buffer[DATA_BUFFER_LEN];
  SendHeader header;
  
  if (getHeader(sockfd, &header)) {
    fprintf(stderr, "Error receiving send header\n");
    exit(1);
  }
  size_t bytesLeft = (size_t)header;
  printf("Recieving file: %zu bytes.\n", bytesLeft);
  while (bytesLeft > 0) {
    size_t readSize = (bytesLeft < DATA_BUFFER_LEN) ? bytesLeft : DATA_BUFFER_LEN;
    n = recv(sockfd, buffer, readSize, 0);
    
    if (n == -1 || n == 0) break;
    fwrite(buffer, 1, n, f);
    bytesLeft -= n;
  }
  fclose(f);

  return 0;
}


int getConnectionInfo(const char *addr, const char *port, struct addrinfo **results) {
  struct addrinfo hints, *res;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (addr == NULL)
    hints.ai_flags = AI_PASSIVE;

  int status = 0;
  if ((status = getaddrinfo(addr, port, &hints, results)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  return 0;
}

int socketBind(int sockfd, struct addrinfo *res) {
  if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
    close(sockfd);
    fprintf(stderr, "Binding error\n");
    return -1;
  }
  return 0;
}

int socketConnect(int sockfd, struct addrinfo *res) {
  if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
    close(sockfd);
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}


int initSockCon(struct addrinfo *res, int (*action)(int, struct addrinfo *)) {
  struct addrinfo *p = NULL;
  int sockfd = -1;

  if (!action) {
    fprintf(stderr, "No socket initialization action provided.\n");
    return -1;
  }
  
  for (p = res; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket error: ");
      continue;
    }
    if (action(sockfd, res) == -1) continue;
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "Failed to apply socket action\n");
    return -1;
  }

  return sockfd;
}

int serverInit(const char *port, struct addrinfo **res, const char *directory) {
  if (getConnectionInfo(NULL, port, res)) return -1;

  int sockfd = -1;
  if ((sockfd = initSockCon(*res, &socketBind)) == -1) {
    fprintf(stderr, "Failed to bind socket\n");
    return -1;
  }

  if (listen(sockfd, BACK_LOG) < 0) {
    fprintf(stderr, "listen: %s\n", strerror(errno));
    return -1;
  }

  return sockfd;
}


void server(char *port) {
  printf("STARTING SERVER MODE\n\n\n");
  struct addrinfo *res;
  struct sockaddr_storage clientAddr;
  socklen_t clientAddrSize = sizeof(clientAddr);
  
  int listenFd = serverInit(port, &res, NULL);
  if (listenFd < 0) exit(1);

  char keepAlive = 1;
  ServerStates curState = SERVER_WAITING_CON;
  int clientSockFd = -1;

  FileMetaData nfile;
  while(keepAlive) {
    switch(curState) {
      //No client connected currently
    case SERVER_WAITING_CON:
      clientSockFd = accept(listenFd, (struct sockaddr *)&clientAddr, &clientAddrSize);
      if (clientSockFd < 0) {
        perror("Accept error: ");
        keepAlive = 0;
      }
      curState = SERVER_CLIENT_CON;
      break;
      //Client connected, nothing happening
    case SERVER_CLIENT_CON: {
      memset(&nfile, 0, sizeof(nfile));
      recvPacket(clientSockFd, &nfile);
      curState = SERVER_CLIENT_TRANSFER;
    }break;
      //Client sending data to server
    case SERVER_CLIENT_TRANSFER:
      recvFile(clientSockFd, &nfile);
      curState = SERVER_CLIENT_DISCON;
      break;

    case SERVER_CLIENT_DISCON:
      keepAlive = 0;
      break;
    }
  }
  
  freeaddrinfo(res);
}


int clientInit(const char *addr, const char *port, struct addrinfo **res) {
  if (getConnectionInfo(addr, port, res)) return -1;

  int sockfd = -1;
  if ((sockfd = initSockCon(*res, &socketConnect)) == -1) {
    fprintf(stderr, "Failed to connect to socket\n");
    return -1;
  }

  return sockfd;
}

void client(const char *server, const char *port, int argc, char *argv[], int offset) {
  printf("STARTING CLIENT MODE\n\n\n");
  struct addrinfo *res;
  int servSock = clientInit(server, port, &res);
  if (servSock < 0) exit(1);
  
  ClientStates curState = CLIENT_SEND_META;
  char keepAlive = 1;
  char *curFile;
  FileMetaData file;
  while (keepAlive) {
    switch(curState) {
    case CLIENT_SEND_META: {
      curFile = argv[offset++];

      file = (FileMetaData) {
        .pathLen = strlen(curFile),
        .type = FILETYPE_FILE,
        .localPath = curFile
      };

      if (file.type == FILETYPE_FILE) {
        file.path = basename(curFile);
      }
      size_t size = 0;
      char *packet = makeFileData(&file, &size);
      sendPackedData(servSock, packet, size);
      curState = CLIENT_META_SENT;
    }break;
    case CLIENT_META_SENT:
      printf("metadata sent, waiting back\n");
      curState = CLIENT_SEND_FILE;
      break;
    case CLIENT_SEND_FILE:
      sendFile(servSock, file.localPath);
      curState = CLIENT_FILE_SENT;
      break;
    case CLIENT_FILE_SENT:
      keepAlive = 0;
      break;
    }
  }
  freeaddrinfo(res);
}


int main(int argc, char *argv[]) {
  char *addr = NULL, *port = NULL;
  int opt;
  while ((opt = getopt(argc, argv, "s:p:")) != -1) {
    switch (opt) {
    case 's':
      addr = optarg;
      break;
    case 'p':
      port = optarg;
      break;
    }
  }

  if (!addr) addr = "127.0.0.1";
  if (!port) port = TEST_PORT;
  
  if (argc < 2) server(port);
  else client(addr, port, argc, argv, optind);

  return 0;
}
