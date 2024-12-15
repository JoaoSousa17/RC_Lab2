#include <stdio.h>          // Para funções de input/output
#include <stdlib.h>         // Para funções gerais como malloc, free
#include <string.h>         // Para manipulação de strings
#include <netdb.h>          // Para funções de rede como gethostbyname
#include <netinet/in.h>     // Para estruturas e funções de rede
#include <arpa/inet.h>      // Para estruturas e funções de rede
#include <sys/socket.h>     // Para funcionalidades de sockets
#include <unistd.h>         // Para funções UNIX como read, write, close
#include <libgen.h>         // Para função basename
#include <errno.h>          // Para tratamento de erros
#include <time.h>           // Para funções relacionadas a tempo

/* Definições de constantes */
#define MAX_LENGTH 1024     // Tamanho máximo para buffers gerais
#define BUFFER_SIZE 8192    // Tamanho do buffer para transferência de dados
#define FTP_PORT 21         // Porta padrão do FTP
#define DEBUG 1             // Flag para ativar/desativar mensagens de debug
#define MAX_ATTEMPTS 3      // Número máximo de tentativas de conexão
#define TIMEOUT_SECONDS 10  // Tempo limite para operações de socket

/* Códigos de resposta do protocolo FTP */
#define FTP_CODE_LOGIN_SUCCESS 230          // Código de login bem sucedido
#define FTP_CODE_PASSIVE_SUCCESS 227        // Código de modo passivo aceito
#define FTP_CODE_TRANSFER_COMPLETE 226      // Código de transferência completa
#define FTP_CODE_FILE_OK 150                // Código de arquivo pronto para transferência
#define FTP_CODE_TRANSFER_START 125         // Código de início de transferência

 /* Estrutura para armazenar informações da URL */
typedef struct {
    char* user;
    char* password;
    char* host;
    char* path;
} URL;

/* Protótipos das funções */
int parseURL(const char* url, URL* parsedUrl);
int connectToServer(const char* ip, int port);
int sendCommand(int sockfd, const char* command, char* response);
int readResponse(int sockfd, char* response);
int getResponseCode(const char* response);
int enterPassiveMode(int sockfd, char* ip, int* port);
void cleanupURL(URL* url);
void setSocketTimeout(int sockfd, int seconds);

/*
 * Função para imprimir mensagens de debug
 * Só imprime se DEBUG estiver a 1 (linha 17)
 */
void debugPrint(const char* msg, const char* info) {
    if (DEBUG) {
        fprintf(stderr, "DEBUG: %s %s\n", msg, info ? info : "");
    }
}

/*  * Configura os timeouts de leitura e escrita para um socket */
void setSocketTimeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    // Configura timeout para recebimento de dados
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
    }
    
    // Configura timeout para envio de dados
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
    }
} 

/*
 * Cliente FTP para download de ficheiros de servidores FTP remotos.
 * Suporta autenticação com username/password ou modo anónimo.
 * 
 * Funcionamento:
 * 1. Faz parse da URL FTP fornecida
 * 2. Estabelece conexão com o servidor e autentica
 * 3. Inicia transferência em modo binário e passivo
 * 4. Faz download do ficheiro com monitorização de progresso
 * 5. Lida com erros de rede e disco durante a transferência
 */
int main(int argc, char* argv[]) {
    // Verifica se recebeu o argumento correto (URL do FTP)
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

    // Resolve o hostname para IP
    struct hostent* h;
    if ((h = gethostbyname(parsedUrl.host)) == NULL) {
        fprintf(stderr, "Error getting host by name\n");
        cleanupURL(&parsedUrl);
        exit(1);
    }
    
    char* ip = inet_ntoa(*((struct in_addr*)h->h_addr));
    debugPrint("IP address:", ip);

    // Conecta ao socket de controle na porta 21
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

    char command[MAX_LENGTH];

    // Envia username
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

    // Envia password
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

    // Configura modo binário
    debugPrint("Setting binary mode", "");
    if (sendCommand(controlSocket, "TYPE I\r\n", response) < 0) {
        debugPrint("TYPE I failed:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("TYPE I response:", response);

    // Entra em modo passivo
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

    // Conecta ao socket de dados
    int dataSocket = connectToServer(pasvIP, pasvPort);
    if (dataSocket < 0) {
        debugPrint("Data connection failed", "");
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("Data connection established", "");

    // Solicita o arquivo
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

    // Abre ficheiro local para escrita
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

    // Variaveis para recebimento de dados
    char buffer[BUFFER_SIZE];
    int bytes;
    long totalBytes = 0;
    int retryCount = 0;
    time_t startTime = time(NULL);

    while ((bytes = read(dataSocket, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, bytes, file) < bytes) {   // Tratamento de erros de escrita
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
        
        // Mostra velocidade de transferência a cada 5 segundos
        totalBytes += bytes;
        if (DEBUG) {
            fprintf(stderr, "\rDEBUG: Received %ld bytes", totalBytes);
            fflush(stderr);
        }
        
        retryCount = 0; 
        
        // Mostra a velocidade da transferência a cada 5 segundos
        time_t now = time(NULL);
        if (now - startTime >= 5) {
            double speed = totalBytes / (now - startTime) / 1024.0;
            fprintf(stderr, "\nTransfer speed: %.2f KB/s\n", speed);
            startTime = now;
            totalBytes = 0;
        }
    }

    // Verifica erros críticos de leitura do socket, ignorando timeouts temporários
    if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("Error reading from socket");
        fclose(file);
        close(dataSocket);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }

    debugPrint("\nTransfer complete. Total bytes:", "");

    // Fecha a conexão e o ficheiro
    fclose(file);
    close(dataSocket);
    debugPrint("Data connection closed", "");

    // Lê mensagem de conclusão da transferência
    if (readResponse(controlSocket, response) < 0 ||
        getResponseCode(response) != FTP_CODE_TRANSFER_COMPLETE) {
        fprintf(stderr, "Transfer failed\n");
        debugPrint("Transfer completion response:", response);
        close(controlSocket);
        cleanupURL(&parsedUrl);
        exit(1);
    }
    debugPrint("Transfer completion response:", response);

    // Envia comando QUIT e fecha conexões
    sendCommand(controlSocket, "QUIT\r\n", response);
    close(controlSocket);
    cleanupURL(&parsedUrl);
    printf("Download completed successfully\n");
    return 0;
}

/*
 * Função que analisa uma URL FTP e extrai seus componentes
 * Parâmetros:
 *   url: string contendo a URL completa
 *   parsedUrl: ponteiro para estrutura onde serão armazenados os componentes
 * Retorno:
 *   0 em caso de sucesso
 *   -1 em caso de erro
 */
int parseURL(const char* url, URL* parsedUrl) {
    if (strncmp(url, "ftp://", 6) != 0) {       // Verifica se a URL começa com "ftp://"
        return -1;
    }

    // Cria uma cópia da URL sem o prefixo "ftp://"
    char* urlCopy = strdup(url + 6);
    char* cursor = urlCopy;
    char* at = strchr(cursor, '@');             // Procura pelo caractere '@' que separa credenciais do host

    // Se encontrou '@', processa usuário e senha
    if (at) {
        *at = '\0';
        char* colon = strchr(cursor, ':');
        if (colon) {    // Se encontrou ':', separa usuário e senha
            *colon = '\0';
            parsedUrl->user = strdup(cursor);
            parsedUrl->password = strdup(colon + 1);
        } else {        // Se não encontrou ':', só tem usuário
            parsedUrl->user = strdup(cursor);
            parsedUrl->password = strdup("");
        }
        cursor = at + 1;
    }

    // Procura '/' que separa host do caminho
    char* slash = strchr(cursor, '/');
    if (slash) {        // Se encontrou '/', separa host e caminho
        *slash = '\0';
        parsedUrl->host = strdup(cursor);
        parsedUrl->path = strdup(slash + 1);
    } else {            // Se não encontrou '/', só tem host
        parsedUrl->host = strdup(cursor);
        parsedUrl->path = strdup("");
    }

    free(urlCopy);
    return 0;
}

/*
 * Função que estabelece conexão com o servidor FTP
 * Parâmetros:
 *   ip: endereço IP do servidor
 *   port: porta para conexão
 * Retorno:
 *   descritor do socket em caso de sucesso
 *   -1 em caso de erro
 */
int connectToServer(const char* ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    int attempt = 0;
    
    // Tenta conectar até MAX_ATTEMPTS vezes
    while (attempt < MAX_ATTEMPTS) {
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {       // Cria um socket TCP/IP
            return -1;
        }
        
        setSocketTimeout(sockfd, TIMEOUT_SECONDS);
        
        // Inicializa estrutura de endereço do servidor
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {   // Converte IP string para formato binário
            close(sockfd);
            return -1;
        }
        
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {    // Tenta estabelecer conexão
            return sockfd;
        }
        
        close(sockfd);
        attempt++;
        sleep(1);
    }
    
    return -1;
}

/*
 * Função que envia um comando FTP para o servidor e lê a resposta
 * Parâmetros:
 *   sockfd: descritor do socket
 *   command: comando FTP a ser enviado
 *   response: buffer onde será armazenada a resposta
 * Retorno:
 *   0 em caso de sucesso
 *   -1 em caso de erro
 */
int sendCommand(int sockfd, const char* command, char* response) {
    if (write(sockfd, command, strlen(command)) < 0) {
        return -1;
    }
    return readResponse(sockfd, response);
}

/*
 * Função que lê a resposta do servidor FTP
 * Parâmetros:
 *   sockfd: descritor do socket
 *   response: buffer onde será armazenada a resposta
 * Retorno:
 *   0 em caso de sucesso
 *   -1 em caso de erro
 */
int readResponse(int sockfd, char* response) {
    memset(response, 0, MAX_LENGTH);
    char buffer[MAX_LENGTH];
    int total = 0;
    int complete = 0;
    
    // Primeira leitura
    int bytes = read(sockfd, buffer, sizeof(buffer)-1);
    if (bytes <= 0) {
        debugPrint("First read failed with bytes:", "");
        return -1;
    }
    
    buffer[bytes] = '\0';
    strcat(response, buffer);
    total += bytes;

    // Se é uma resposta simples (como o banner inicial)
    if (response[0] >= '0' && response[0] <= '9' && 
        total >= 4 && response[3] == ' ') {
        return 0;
    }
    
    // Para respostas multi-linha
    while (!complete && total < MAX_LENGTH - 1) {
        // Verifica se já temos uma resposta completa
        char* lastLine = strrchr(response, '\n');
        if (lastLine) {
            // Retrocede para início da última linha
            while (lastLine > response && *(lastLine-1) != '\n') {
                lastLine--;
            }
            
            // Verifica se é uma linha final válida
            int code;
            char sep;
            if (sscanf(lastLine, "%d%c", &code, &sep) == 2 && sep == ' ') {
                complete = 1;
                break;
            }
        }
        
        // Lê mais dados se necessário
        bytes = read(sockfd, buffer, sizeof(buffer)-1);
        if (bytes <= 0) break;
        
        buffer[bytes] = '\0';
        strcat(response, buffer);
        total += bytes;
    }
    
    debugPrint("Complete response:", response);
    return complete ? 0 : -1;
}

/*
 * Função que extrai o código numérico da resposta FTP
 * Parâmetros:
 *   response: string contendo a resposta do servidor
 * Retorno:
 *   código numérico em caso de sucesso
 *   -1 em caso de erro
 */
int getResponseCode(const char* response) {
    int code;
    if (sscanf(response, "%d", &code) != 1) {
        return -1;
    }
    return code;
}

/*
 * Função que coloca o servidor em modo passivo
 * Parâmetros:
 *   sockfd: descritor do socket
 *   ip: buffer onde será armazenado o IP para conexão
 *   port: ponteiro onde será armazenada a porta para conexão
 * Retorno:
 *   0 em caso de sucesso
 *   -1 em caso de erro
 */
int enterPassiveMode(int sockfd, char* ip, int* port) {
    char response[MAX_LENGTH];

    // Envia comando PASV e verifica resposta
    if (sendCommand(sockfd, "PASV\r\n", response) < 0 ||
        getResponseCode(response) != FTP_CODE_PASSIVE_SUCCESS) {
        return -1;
    }

    int ip1, ip2, ip3, ip4, p1, p2;

    // Localiza início dos números na resposta
    char* start = strchr(response, '(');
    if (!start) return -1;
    
    // Extrai os 6 números da resposta
    if (sscanf(start, "(%d,%d,%d,%d,%d,%d)",
               &ip1, &ip2, &ip3, &ip4, &p1, &p2) != 6) {
        return -1;
    }

    snprintf(ip, 16, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);    // Monta o IP em formato string
    *port = p1 * 256 + p2;                                  // Calcula a porta (p1 * 256 + p2)
    return 0;
}

/*
 * Função que libera a memória alocada para a estrutura URL
 * Parâmetros:
 *   url: ponteiro para a estrutura URL
 */
void cleanupURL(URL* url) {
    if (url->user) free(url->user);
    if (url->password) free(url->password);
    if (url->host) free(url->host);
    if (url->path) free(url->path);
}
