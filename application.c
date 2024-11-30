#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>

#define MAX_LENGTH 1024
#define BUFFER_SIZE 8192
#define FTP_PORT 21
#define DEBUG 1
#define MAX_ATTEMPTS 3
#define TIMEOUT_SECONDS 10

// FTP response codes
#define FTP_CODE_LOGIN_SUCCESS 230
#define FTP_CODE_PASSIVE_SUCCESS 227
#define FTP_CODE_TRANSFER_COMPLETE 226
#define FTP_CODE_FILE_OK 150
#define FTP_CODE_TRANSFER_START 125

typedef struct {
    char* user;
    char* password;
    char* host;
    char* path;
} URL;

// Function prototypes
int parseURL(const char* url, URL* parsedUrl);
int connectToServer(const char* ip, int port);
int sendCommand(int sockfd, const char* command, char* response);
int readResponse(int sockfd, char* response);
int getResponseCode(const char* response);
int enterPassiveMode(int sockfd, char* ip, int* port);
void cleanupURL(URL* url);
void setSocketTimeout(int sockfd, int seconds);

void debugPrint(const char* msg, const char* info) {
    if (DEBUG) {
        fprintf(stderr, "DEBUG: %s %s\n", msg, info ? info : "");
    }
}

void setSocketTimeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s ftp://[<user>:<password>@]<host>/<url-path>\n", argv[0]);
        exit(1);
    }

    debugPrint("Starting with URL:", argv[1]);

    // Parse URL
    URL parsedUrl = {0};
    if (parseURL(argv[1], &parsedUrl) < 0) {
        fprintf(stderr, "Error parsing URL\n");
        exit(1);
    }

    debugPrint("Host:", parsedUrl.host);
    debugPrint("Path:", parsedUrl.path);
    debugPrint("User:", parsedUrl.user ? parsedUrl.user : "anonymous");

    // Get IP from hostname
    struct hostent* h;
    if ((h = gethostbyname(parsedUrl.host)) == NULL) {
        fprintf(stderr, "Error getting host by name\n");
        cleanupURL(&parsedUrl);
        exit(1);
    }
    
    char* ip = inet_ntoa(*((struct in_addr*)h->h_addr));
    debugPrint("IP address:", ip);

    // Connect to control socket
    int controlSocket = connectToServer(ip, FTP_PORT);
    if (controlSocket < 0) {
        fprintf(stderr, "Error connecting to server\n");
        cleanupURL(&parsedUrl);
        exit(1);
    }
    
    debugPrint("Connected to control port", "21");

    char response[MAX_LENGTH];
    // Read initial response
    if (readResponse(controlSocket, response) < 0) {
        debugPrint("Error reading initial response", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    
    debugPrint("Initial response:", response);

    // Login process
    char command[MAX_LENGTH];
    // Send username
    snprintf(command, sizeof(command), "USER %s\r\n", 
             parsedUrl.user ? parsedUrl.user : "anonymous");
    debugPrint("Sending USER command:", command);
    
    if (sendCommand(controlSocket, command, response) < 0) {
        debugPrint("USER command failed:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("USER response:", response);

    // Send password
    snprintf(command, sizeof(command), "PASS %s\r\n", 
             parsedUrl.password ? parsedUrl.password : "anonymous@");
    debugPrint("Sending PASS command", "****");
    
    if (sendCommand(controlSocket, command, response) < 0 ||
        getResponseCode(response) != FTP_CODE_LOGIN_SUCCESS) {
        fprintf(stderr, "Login failed\n");
        debugPrint("PASS response:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("PASS response:", response);

    // Set binary mode
    debugPrint("Setting binary mode", "");
    if (sendCommand(controlSocket, "TYPE I\r\n", response) < 0) {
        debugPrint("TYPE I failed:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("TYPE I response:", response);

    // Enter passive mode
    char pasvIP[16];
    int pasvPort;
    debugPrint("Entering passive mode", "");
    
    if (enterPassiveMode(controlSocket, pasvIP, &pasvPort) < 0) {
        debugPrint("PASV failed", "");
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    
    char pasvInfo[50];
    snprintf(pasvInfo, sizeof(pasvInfo), "IP: %s, Port: %d", pasvIP, pasvPort);
    debugPrint("PASV info:", pasvInfo);

    // Connect data socket
    int dataSocket = connectToServer(pasvIP, pasvPort);
    if (dataSocket < 0) {
        debugPrint("Data connection failed", "");
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("Data connection established", "");

    // Request file
    snprintf(command, sizeof(command), "RETR %s\r\n", parsedUrl.path);
    debugPrint("Sending RETR command:", command);
    
    if (sendCommand(controlSocket, command, response) < 0) {
        debugPrint("RETR command failed:", response);
        close(dataSocket);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("RETR response:", response);

    int responseCode = getResponseCode(response);
    if (responseCode != FTP_CODE_FILE_OK && responseCode != FTP_CODE_TRANSFER_START) {
        fprintf(stderr, "Error requesting file: %s\n", response);
        debugPrint("Invalid response code for RETR:", response);
        close(dataSocket);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }

    // Open local file for writing
    char* filename = basename(parsedUrl.path);
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening local file");
        close(dataSocket);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("Local file opened:", filename);

    // Receive data
    char buffer[BUFFER_SIZE];
    int bytes;
    long totalBytes = 0;
    int retryCount = 0;
    time_t startTime = time(NULL);

    while ((bytes = read(dataSocket, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, bytes, file) < bytes) {
            if (errno == ENOSPC) {
                fprintf(stderr, "Error: No space left on device\n");
                fclose(file);
                close(dataSocket);
                close(controlSocket);
                cleanupURL(&parsedUrl);
                exit(1);
            }
            
            if (retryCount < MAX_ATTEMPTS) {
                retryCount++;
                continue;
            }
            
            perror("Error writing to file");
            fclose(file);
            close(dataSocket);
            close(controlSocket);
            cleanupURL(&parsedUrl);
            exit(1);
        }
        
        totalBytes += bytes;
        if (DEBUG) {
            fprintf(stderr, "\rDEBUG: Received %ld bytes", totalBytes);
            fflush(stderr);
        }
        
        retryCount = 0;  // Reset retry counter on successful write
        
        // Show transfer speed every 5 seconds
        time_t now = time(NULL);
        if (now - startTime >= 5) {
            double speed = totalBytes / (now - startTime) / 1024.0;
            fprintf(stderr, "\nTransfer speed: %.2f KB/s\n", speed);
            startTime = now;
            totalBytes = 0;
        }
    }

    if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("Error reading from socket");
        fclose(file);
        close(dataSocket);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }

    debugPrint("\nTransfer complete. Total bytes:", "");

    // Close data connection and file
    fclose(file);
    close(dataSocket);
    debugPrint("Data connection closed", "");

    // Read transfer complete message
    if (readResponse(controlSocket, response) < 0 ||
        getResponseCode(response) != FTP_CODE_TRANSFER_COMPLETE) {
        fprintf(stderr, "Transfer failed\n");
        debugPrint("Transfer completion response:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("Transfer completion response:", response);

    // Quit and cleanup
    sendCommand(controlSocket, "QUIT\r\n", response);
    close(controlSocket);
    cleanupURL(&parsedUrl);
    printf("Download completed successfully\n");
    return 0;
}

int parseURL(const char* url, URL* parsedUrl) {
    if (strncmp(url, "ftp://", 6) != 0) {
        return -1;
    }

    char* urlCopy = strdup(url + 6);
    char* cursor = urlCopy;
    char* at = strchr(cursor, '@');

    if (at) {
        // Extract username and password
        *at = '\0';
        char* colon = strchr(cursor, ':');
        if (colon) {
            *colon = '\0';
            parsedUrl->user = strdup(cursor);
            parsedUrl->password = strdup(colon + 1);
        } else {
            parsedUrl->user = strdup(cursor);
            parsedUrl->password = strdup("");
        }
        cursor = at + 1;
    }

    // Extract host and path
    char* slash = strchr(cursor, '/');
    if (slash) {
        *slash = '\0';
        parsedUrl->host = strdup(cursor);
        parsedUrl->path = strdup(slash + 1);
    } else {
        parsedUrl->host = strdup(cursor);
        parsedUrl->path = strdup("");
    }

    free(urlCopy);
    return 0;
}

int connectToServer(const char* ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    int attempt = 0;
    
    while (attempt < MAX_ATTEMPTS) {
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            return -1;
        }
        
        // Set socket timeout
        setSocketTimeout(sockfd, TIMEOUT_SECONDS);
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
            close(sockfd);
            return -1;
        }
        
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            return sockfd;
        }
        
        close(sockfd);
        attempt++;
        sleep(1); // Wait 1 second before trying again
    }
    
    return -1;
}

int sendCommand(int sockfd, const char* command, char* response) {
    if (write(sockfd, command, strlen(command)) < 0) {
        return -1;
    }
    return readResponse(sockfd, response);
}

int readResponse(int sockfd, char* response) {
    memset(response, 0, MAX_LENGTH);
    char buffer[MAX_LENGTH];
    int total = 0;
    int complete = 0;
    
    while (!complete && total < MAX_LENGTH - 1) {
        int bytes = read(sockfd, buffer, sizeof(buffer)-1);
        if (bytes <= 0) return -1;
        
        buffer[bytes] = '\0';
        strcat(response, buffer);
        total += bytes;
        
        // Check if response is complete (ends with \r\n)
        if (total >= 2 && 
            response[total-2] == '\r' && 
            response[total-1] == '\n') {
            complete = 1;
        }
    }
    
    return 0;
}

int getResponseCode(const char* response) {
    int code;
    if (sscanf(response, "%d", &code) != 1) {
        return -1;
    }
    return code;
}

int enterPassiveMode(int sockfd, char* ip, int* port) {
    char response[MAX_LENGTH];
    if (sendCommand(sockfd, "PASV\r\n", response) < 0 ||
        getResponseCode(response) != FTP_CODE_PASSIVE_SUCCESS) {
        return -1;
    }

    int ip1, ip2, ip3, ip4, p1, p2;
    char* start = strchr(response, '(');
    if (!start) return -1;
    
    if (sscanf(start, "(%d,%d,%d,%d,%d,%d)",
               &ip1, &ip2, &ip3, &ip4, &p1, &p2) != 6) {
        return -1;
    }

    snprintf(ip, 16, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
    *port = p1 * 256 + p2;
    return 0;
}

void cleanupURL(URL* url) {
    if (url->user) free(url->user);
    if (url->password) free(url->password);
    if (url->host) free(url->host);
    if (url->path) free(url->path);
}
