#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define FTP_PORT 21
#define MAX_BUFFER_SIZE 1024
#define RESPONSE_SIZE 4096

// Structure to hold FTP connection information
typedef struct {
    int control_socket;
    int data_socket;
    char buffer[MAX_BUFFER_SIZE];
    char response[RESPONSE_SIZE];
} ftp_connection;

// Function prototypes
int connect_to_server(const char* hostname, int port);
int read_reply(ftp_connection* ftp);
int send_command(ftp_connection* ftp, const char* command);
int login(ftp_connection* ftp, const char* username, const char* password);
int enter_passive_mode(ftp_connection* ftp);
int download_file(ftp_connection* ftp, const char* filename);
void close_connection(ftp_connection* ftp);

// Main function
int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <hostname> <username> <password> <filename>\n", argv[0]);
        exit(1);
    }

    ftp_connection ftp = {0};
    
    // Connect to server
    ftp.control_socket = connect_to_server(argv[1], FTP_PORT);
    if (ftp.control_socket < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        exit(1);
    }

    // Read welcome message
    if (read_reply(&ftp) < 0) {
        fprintf(stderr, "Error reading welcome message\n");
        close_connection(&ftp);
        exit(1);
    }

    // Login
    if (login(&ftp, argv[2], argv[3]) < 0) {
        fprintf(stderr, "Login failed\n");
        close_connection(&ftp);
        exit(1);
    }

    // Set binary mode
    if (send_command(&ftp, "TYPE I\r\n") < 0) {
        fprintf(stderr, "Failed to set binary mode\n");
        close_connection(&ftp);
        exit(1);
    }
    read_reply(&ftp);

    // Enter passive mode and download file
    if (enter_passive_mode(&ftp) < 0) {
        fprintf(stderr, "Failed to enter passive mode\n");
        close_connection(&ftp);
        exit(1);
    }

    if (download_file(&ftp, argv[4]) < 0) {
        fprintf(stderr, "Failed to download file\n");
        close_connection(&ftp);
        exit(1);
    }

    // Close connection
    send_command(&ftp, "QUIT\r\n");
    read_reply(&ftp);
    close_connection(&ftp);

    return 0;
}

// Connect to FTP server
int connect_to_server(const char* hostname, int port) {
    struct hostent* host;
    struct sockaddr_in server_addr;
    int sockfd;

    // Get host by name
    host = gethostbyname(hostname);
    if (host == NULL) {
        herror("gethostbyname()");
        return -1;
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket()");
        return -1;
    }

    // Setup server address structure
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect()");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Read server reply
int read_reply(ftp_connection* ftp) {
    int bytes = 0;
    int total = 0;
    memset(ftp->response, 0, RESPONSE_SIZE);

    while ((bytes = read(ftp->control_socket, ftp->response + total, RESPONSE_SIZE - total)) > 0) {
        total += bytes;
        if (total >= 2 && ftp->response[total-2] == '\r' && ftp->response[total-1] == '\n') {
            break;
        }
    }

    if (bytes < 0) {
        perror("read()");
        return -1;
    }

    printf("Server response: %s", ftp->response);
    return 0;
}

// Send command to server
int send_command(ftp_connection* ftp, const char* command) {
    printf("Sending command: %s", command);
    if (write(ftp->control_socket, command, strlen(command)) < 0) {
        perror("write()");
        return -1;
    }
    return 0;
}

// Login to FTP server
int login(ftp_connection* ftp, const char* username, const char* password) {
    char command[MAX_BUFFER_SIZE];

    // Send username
    snprintf(command, sizeof(command), "USER %s\r\n", username);
    if (send_command(ftp, command) < 0) return -1;
    if (read_reply(ftp) < 0) return -1;

    // Send password
    snprintf(command, sizeof(command), "PASS %s\r\n", password);
    if (send_command(ftp, command) < 0) return -1;
    if (read_reply(ftp) < 0) return -1;

    return 0;
}

// Enter passive mode
int enter_passive_mode(ftp_connection* ftp) {
    char* response;
    int ip[4], port[2];

    // Send PASV command
    if (send_command(ftp, "PASV\r\n") < 0) return -1;
    if (read_reply(ftp) < 0) return -1;

    // Parse PASV response
    response = strstr(ftp->response, "(");
    if (!response) return -1;
    sscanf(response, "(%d,%d,%d,%d,%d,%d)",
           &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);

    // Connect to data port
    char ip_str[32];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    int data_port = port[0] * 256 + port[1];

    ftp->data_socket = connect_to_server(ip_str, data_port);
    return ftp->data_socket;
}

// Download file
int download_file(ftp_connection* ftp, const char* filename) {
    char command[MAX_BUFFER_SIZE];
    FILE* file;
    int bytes;

    // Send RETR command
    snprintf(command, sizeof(command), "RETR %s\r\n", filename);
    if (send_command(ftp, command) < 0) return -1;
    if (read_reply(ftp) < 0) return -1;

    // Open local file
    file = fopen(filename, "wb");
    if (!file) {
        perror("fopen()");
        return -1;
    }

    // Read data and write to file
    while ((bytes = read(ftp->data_socket, ftp->buffer, MAX_BUFFER_SIZE)) > 0) {
        if (fwrite(ftp->buffer, 1, bytes, file) != bytes) {
            perror("fwrite()");
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    close(ftp->data_socket);
    read_reply(ftp);  // Read transfer complete message

    return 0;
}

// Close FTP connection
void close_connection(ftp_connection* ftp) {
    if (ftp->data_socket > 0) close(ftp->data_socket);
    if (ftp->control_socket > 0) close(ftp->control_socket);
}