#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <csse2310a4.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <FreeImage.h>
#include <csse2310_freeimage.h>
#include <signal.h>
#include <semaphore.h>

#define MAX_CONNS 10000
#define BODY_INIT_BUFFER 100
#define MAX_FILE_SIZE 8388608
#define MAX_ARGS 5
#define MAX_CON 10
#define HEADER_LIMIT 3
#define ROTATE_MIN (-359)
#define ROTATE_MAX 359
#define SCALE_LIMIT 10000
#define ERROR_BODY 50
#define RESPONSE_BODY 80

// HTTP response codes
typedef enum {
    RESPONSE_OK = 200,
    RESPONSE_BAD_REQUEST = 400,
    RESPONSE_NOT_FOUND = 404,
    RESPONSE_NOT_ALLOWED = 405,
    RESPONSE_PAYLOAD_EXCD_LIMIT = 413,
    RESPONSE_CANNOT_PROCESS = 422,
    RESPONSE_NOT_IMPLEMENTED = 501
} HttpResponseCode;

// Error codes
typedef enum {
    USAGE_ERROR = 7,
    CONNECTION_ERROR = 16,
} ErrorCode;

// Server configuration
typedef struct {
    char* portNum;
    char* maxConns;
    int connSpecified;
} ServerConfig;

// Request information
typedef struct {
    unsigned char* body;
    char* method;
    char* address;
    unsigned long len;
    HttpHeader** headers;
} RequestInfo;

// Server statistics
typedef struct {
    unsigned int currentClients;
    unsigned int numCompletedClients;
    unsigned int successfulRequests;
    unsigned int unsuccessfulRequests;
    unsigned int totalOperations;
} Statistics;

// Shared resources
typedef struct {
    sigset_t sigSet;
    pthread_mutex_t* lock;
    sem_t* semlock;
    int fd;
    int connSpecified;
    Statistics stats;
} SharedResources;

// Function prototypes
void error_handler(ErrorCode code, const char* message);
ServerConfig parse_command_line(int argc, char** argv);
int establish_listening_connection(const ServerConfig* config);
void* client_thread(void* arg);
void* sighup_thread(void* arg);
int process_request(RequestInfo* request, FILE* to, SharedResources* resources);
void free_request_info(RequestInfo* request);
int check_invalid_method(RequestInfo request, FILE* to);
int check_invalid_address(RequestInfo request, FILE* to);
void check_home(RequestInfo request, FILE* to);
int check_individual_field_scale(char** fieldCheck);
int check_individual_field_flip(char** fieldCheck);
int check_individual_field(char** fieldCheck);
int check_invalid_operation_preliminary(RequestInfo request);
void invalid_operation_response(FILE* to);
char** check_invalid_operation_values(RequestInfo request, FILE* to);
int send_final_image(FILE* to, const unsigned char* image, unsigned long newLen);
void invalid_image_operation(FILE* to, char* operation);
int invalid_image_check(FILE* to);
int image_too_large_check(RequestInfo request, FILE* to);
int image_generation(RequestInfo request, FILE* to, SharedResources* resources);
int check_request_validity(RequestInfo request, FILE* to, SharedResources* resources);

// Error handler function
void error_handler(ErrorCode code, const char* message) {
    fprintf(stderr, "%s\n", message);
    exit(code);
}

// Parse command line arguments
ServerConfig parse_command_line(int argc, char** argv) {
    ServerConfig config = {NULL, NULL, 0};
    config.portNum = "0";  // Default port

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--maxConns") == 0) {
            if (i + 1 < argc) {
                int maxConns = atoi(argv[++i]);
                if (maxConns > 0 && maxConns <= MAX_CONNS) {
                    config.maxConns = argv[i];
                    config.connSpecified = 1;
                } else {
                    error_handler(USAGE_ERROR, "Usage: uqimageproc [--listenOn portnum] [--maxConns n]");
                }
            } else {
                error_handler(USAGE_ERROR, "Usage: uqimageproc [--listenOn portnum] [--maxConns n]");
            }
        } else if (strcmp(argv[i], "--listenOn") == 0) {
            if (i + 1 < argc) {
                config.portNum = argv[++i];
            } else {
                error_handler(USAGE_ERROR, "Usage: uqimageproc [--listenOn portnum] [--maxConns n]");
            }
        } else {
            error_handler(USAGE_ERROR, "Usage: uqimageproc [--listenOn portnum] [--maxConns n]");
        }
    }

    return config;
}

// Establish listening connection
int establish_listening_connection(const ServerConfig* config) {
    struct addrinfo hints = {0}, *ai = 0;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int err;
    if ((err = getaddrinfo(NULL, config->portNum, &hints, &ai))) {
        freeaddrinfo(ai);
        error_handler(CONNECTION_ERROR, "Cannot listen on given port");
    }

    int serv = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(serv, ai->ai_addr, sizeof(struct sockaddr))) {
        freeaddrinfo(ai);
        error_handler(CONNECTION_ERROR, "Cannot listen on given port");
    }
    freeaddrinfo(ai);

    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(serv, (struct sockaddr*)&ad, &len)) {
        error_handler(CONNECTION_ERROR, "Cannot listen on given port");
    }
    fprintf(stderr, "%u\n", ntohs(ad.sin_port));

    if (listen(serv, MAX_CON)) {
        error_handler(CONNECTION_ERROR, "Cannot listen on given port");
    }

    return serv;
}

// Client thread function
void* client_thread(void* arg) {
    SharedResources* resources = (SharedResources*)arg;
    FILE* from = fdopen(dup(resources->fd), "r");
    FILE* to = fdopen(resources->fd, "w");

    pthread_mutex_lock(resources->lock);
    resources->stats.currentClients++;
    pthread_mutex_unlock(resources->lock);

    while (1) {
        RequestInfo request = {0};
        if (get_HTTP_request(from, &request.method, &request.address, 
                             &request.headers, &request.body, &request.len) == 0) {
            break;
        }

        int success = process_request(&request, to, resources);

        pthread_mutex_lock(resources->lock);
        if (success) {
            resources->stats.successfulRequests++;
        } else {
            resources->stats.unsuccessfulRequests++;
        }
        pthread_mutex_unlock(resources->lock);

        free_request_info(&request);
    }

    pthread_mutex_lock(resources->lock);
    resources->stats.numCompletedClients++;
    resources->stats.currentClients--;
    pthread_mutex_unlock(resources->lock);

    if (resources->connSpecified) {
        sem_post(resources->semlock);
    }

    fclose(from);
    fclose(to);
    free(resources);
    return NULL;
}

// Process client request
int process_request(RequestInfo* request, FILE* to, SharedResources* resources) {
    if (!request->method) {
        return 0;
    }

    if (check_invalid_method(*request, to) || check_invalid_address(*request, to)) {
        return 0;
    }

    check_home(*request, to);

    if (strcmp(request->method, "POST") == 0) {
        if (check_invalid_operation_preliminary(*request)) {
            invalid_operation_response(to);
            return 0;
        }

        if (check_invalid_operation_values(*request, to) == NULL) {
            return 0;
        }

        if (image_too_large_check(*request, to)) {
            return 0;
        }

        return image_generation(*request, to, resources);
    }

    return 1;
}

void free_request_info(RequestInfo* request) {
    free(request->method);
    free(request->address);
    free(request->body);
    if (request->headers) {
        for (int i = 0; request->headers[i] != NULL; i++) {
            free(request->headers[i]->name);
            free(request->headers[i]->value);
            free(request->headers[i]);
        }
        free(request->headers);
    }
}

// SIGHUP handler
void* sighup_thread(void* arg) {
    SharedResources* resources = (SharedResources*)arg;
    int signal;

    while (1) {
        if (sigwait(&resources->sigSet, &signal) == 0) {
            pthread_mutex_lock(resources->lock);
            fprintf(stderr, "Currently connected clients: %d\n", resources->stats.currentClients);
            fprintf(stderr, "Num completed clients: %d\n", resources->stats.numCompletedClients);
            fprintf(stderr, "Successfully processed HTTP requests: %d\n", resources->stats.successfulRequests);
            fprintf(stderr, "Unsuccessful HTTP requests: %d\n", resources->stats.unsuccessfulRequests);
            fprintf(stderr, "Operations on images: %d\n", resources->stats.totalOperations);
            pthread_mutex_unlock(resources->lock);
            fflush(stderr);
        }
    }

    return NULL;
}

int check_invalid_method(RequestInfo request, FILE* to) {
    if (strcmp(request.method, "GET") && strcmp(request.method, "POST")) {
        const char* body = "Invalid HTTP method\n";
        size_t bodySize = strlen(body);
        char bodySizeConverted[20];
        snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", (unsigned long)bodySize);

        HttpHeader headers[3] = {
            {"Content-Type", "text/plain"},
            {"Content-Length", bodySizeConverted},
            {NULL, NULL}
        };

        unsigned char* httpResponse;
        unsigned long len;
        httpResponse = construct_HTTP_response(RESPONSE_NOT_ALLOWED,
                "Method Not Allowed", headers, (const unsigned char*)body, bodySize, &len);
        fwrite(httpResponse, sizeof(unsigned char), len, to);
        fflush(to);
        free(httpResponse);
        return 1;
    }
    return 0;
}

int check_invalid_address(RequestInfo request, FILE* to) {
    if (!strcmp(request.method, "GET") && (strcmp(request.address, "/"))) {
        const char* body = "Invalid address in GET request\n";
        size_t bodySize = strlen(body);
        char bodySizeConverted[20];
        snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", (unsigned long)bodySize);

        HttpHeader headers[3] = {
            {"Content-Type", "text/plain"},
            {"Content-Length", bodySizeConverted},
            {NULL, NULL}
        };

        unsigned char* httpResponse;
        unsigned long len;
        httpResponse = construct_HTTP_response(RESPONSE_NOT_FOUND,
                "Not Found", headers, (const unsigned char*)body, bodySize, &len);
        fwrite(httpResponse, sizeof(unsigned char), len, to);
        fflush(to);
        free(httpResponse);
        return 1;
    }
    return 0;
}

void check_home(RequestInfo request, FILE* to) {
    if (!strcmp(request.method, "GET") && !strcmp(request.address, "/")) {
        FILE* homePage = fopen("/local/courses/csse2310/resources/a4/home.html", "r");
        if (!homePage) {
            perror("Failed to open home.html!");
            return;
        }

        char* body = NULL;
        size_t bodySize = 0;
        size_t bytesRead = 0;
        char buffer[BODY_INIT_BUFFER];

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), homePage)) > 0) {
            body = realloc(body, bodySize + bytesRead);
            memcpy(body + bodySize, buffer, bytesRead);
            bodySize += bytesRead;
        }

        fclose(homePage);

        char bodySizeConverted[20];
        snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", (unsigned long)bodySize);

        HttpHeader headers[3] = {
            {"Content-Type", "text/html"},
            {"Content-Length", bodySizeConverted},
            {NULL, NULL}
        };

        unsigned char* httpResponse;
        unsigned long len;
        httpResponse = construct_HTTP_response(RESPONSE_OK, "OK", headers, 
                (const unsigned char*)body, bodySize, &len);
      
        fwrite(httpResponse, sizeof(unsigned char), len, to);
        fflush(to);
        free(httpResponse);
        free(body);
    }
}

int check_individual_field_scale(char** fieldCheck) {
    for (int i = 1; i < 3; i++) {
        for (int j = 1; j < (int)strlen(fieldCheck[i]); j++) {
            if (fieldCheck[i][j] == '+' || fieldCheck[i][j] == '-') {
                return 1;
            }
        }
        if (strlen(fieldCheck[i]) == 1 && fieldCheck[i][0] == '0') {
            continue;
        }
        char* endptr;
        long value = strtol(fieldCheck[i], &endptr, 10);
        if (*endptr != '\0' || value < 1 || value > SCALE_LIMIT) {
            return 1;
        }
    }
    return 0;
}

int check_individual_field_flip(char** fieldCheck) {
    return (strlen(fieldCheck[1]) != 1 || (fieldCheck[1][0] != 'h' && fieldCheck[1][0] != 'v'));
}

int check_individual_field(char** fieldCheck) {
    if (strcmp("rotate", fieldCheck[0]) == 0) {
        char* endptr;
        long value = strtol(fieldCheck[1], &endptr, 10);
        if (*endptr != '\0' || value < ROTATE_MIN || value > ROTATE_MAX) {
            return 1;
        }
    } else if (strcmp("flip", fieldCheck[0]) == 0) {
        return check_individual_field_flip(fieldCheck);
    } else if (strcmp("scale", fieldCheck[0]) == 0) {
        return check_individual_field_scale(fieldCheck);
    } else {
        return 1;
    }
    return 0;
}

int check_invalid_operation_preliminary(RequestInfo request) {
    char* address = request.address;
    int addressLen = strlen(address);
    char* copiedOperation = malloc(sizeof(char) * (addressLen + 1));
    strcpy(copiedOperation, address);

    int splitCount = 0;
    char** splitOperation = split_by_char(copiedOperation, '/', &splitCount);

    for (int i = 0; i < addressLen; i++) {
        char c = address[i];
        if (!isalnum(c) && c != '/' && c != ',' && c != '+' && c != '-') {
            free(copiedOperation);
            free(splitOperation);
            return 1;
        }
        if ((c == '/' && (i + 1 < addressLen && (address[i + 1] == '/' || address[i + 1] == ','))) ||
            (c == ',' && (i + 1 < addressLen && (address[i + 1] == ',' || address[i + 1] == '/'))) ||
            c == ' ') {
            free(copiedOperation);
            free(splitOperation);
            return 1;
        }
    }

    for (int i = 0; i < splitCount; i++) {
        int fieldCount = 0;
        char** splitField = split_by_char(splitOperation[i], ',', &fieldCount);
        if (!splitField) {
            free(copiedOperation);
            free(splitOperation);
            return 1;
        }
        if (check_individual_field(splitField)) {
            for (int j = 0; j < fieldCount; j++) {
                free(splitField[j]);
            }
            free(splitField);
            free(copiedOperation);
            free(splitOperation);
            return 1;
        }
        for (int j = 0; j < fieldCount; j++) {
            free(splitField[j]);
        }
        free(splitField);
    }
    free(copiedOperation);
    free(splitOperation);
    return 0;
}

void invalid_operation_response(FILE* to) {
    const char* body = "Invalid image operation\n";
    size_t bodySize = strlen(body);
    char bodySizeConverted[20];
    snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", (unsigned long)bodySize);

    HttpHeader headers[3] = {
        {"Content-Type", "text/plain"},
        {"Content-Length", bodySizeConverted},
        {NULL, NULL}
    };

    unsigned char* httpResponse;
    unsigned long len;
    httpResponse = construct_HTTP_response(RESPONSE_BAD_REQUEST, "Bad Request", 
            headers, (const unsigned char*)body, bodySize, &len);
    fwrite(httpResponse, sizeof(unsigned char), len, to);
    fflush(to);
    free(httpResponse);
}

char** check_invalid_operation_values(RequestInfo request, FILE* to) {
    char* copiedOperation = malloc(sizeof(char) * (strlen(request.address) + 1));
    strcpy(copiedOperation, request.address);
    char** splitOperation = split_by_char(copiedOperation, '/', 0);
    
    for (int i = 0; splitOperation[i] != NULL; i++) {
        char** splitField = split_by_char(splitOperation[i], ',', 0);
        if (!strcmp(splitField[0], "rotate")) {
            int rotateArg = atoi(splitField[1]);
            if (rotateArg > ROTATE_MAX || rotateArg < ROTATE_MIN) {
                invalid_operation_response(to);
                free_split_array(splitField);
                free(copiedOperation);
                free_split_array(splitOperation);
                return NULL;
            }
        }
        if (!strcmp(splitField[0], "scale")) {
            int scaleArgW = atoi(splitField[1]);
            int scaleArgH = atoi(splitField[2]);
            if (scaleArgW > SCALE_LIMIT || scaleArgH > SCALE_LIMIT
                    || scaleArgW < 1 || scaleArgH < 1) {
                invalid_operation_response(to);
                free_split_array(splitField);
                free(copiedOperation);
                free_split_array(splitOperation);
                return NULL;
            }
        }
        free_split_array(splitField);
    }
    free(copiedOperation);
    return splitOperation;
}

int send_final_image(FILE* to, const unsigned char* image, unsigned long newLen) {
    char bodySizeConverted[20];
    snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", newLen);

    HttpHeader headers[3] = {
        {"Content-Type", "image/png"},
        {"Content-Length", bodySizeConverted},
        {NULL, NULL}
    };

    unsigned char* httpResponse;
    unsigned long len;
    httpResponse = construct_HTTP_response(RESPONSE_OK, "OK", headers, image, newLen, &len);
    fwrite(httpResponse, sizeof(unsigned char), len, to);
    fflush(to);
    free(httpResponse);
    return 1;
}

void invalid_image_operation(FILE* to, const char* operation) {
    char errorBody[ERROR_BODY];
    snprintf(errorBody, sizeof(errorBody), "Operation failed: %s\n", operation);
    
    char bodySizeConverted[20];
    snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", strlen(errorBody));

    HttpHeader headers[3] = {
        {"Content-Type", "text/plain"},
        {"Content-Length", bodySizeConverted},
        {NULL, NULL}
    };

    unsigned char* httpResponse;
    unsigned long len;
    httpResponse = construct_HTTP_response(RESPONSE_NOT_IMPLEMENTED, "Not Implemented", 
            headers, (const unsigned char*)errorBody, strlen(errorBody), &len);
    fwrite(httpResponse, sizeof(unsigned char), len, to);
    fflush(to);
    free(httpResponse);
}

int invalid_image_check(FILE* to) {
    const char* body = "Request contains invalid image\n";
    size_t bodySize = strlen(body);
    char bodySizeConverted[20];
    snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", (unsigned long)bodySize);

    HttpHeader headers[3] = {
        {"Content-Type", "text/plain"},
        {"Content-Length", bodySizeConverted},
        {NULL, NULL}
    };

    unsigned char* httpResponse;
    unsigned long len;
    httpResponse = construct_HTTP_response(RESPONSE_CANNOT_PROCESS, "Unprocessable Content", 
            headers, (const unsigned char*)body, bodySize, &len);
    fwrite(httpResponse, sizeof(unsigned char), len, to);
    fflush(to);
    free(httpResponse);
    return 1;
}

int image_too_large_check(RequestInfo request, FILE* to) {
    if (request.len > MAX_FILE_SIZE) {
        char response[RESPONSE_BODY];
        snprintf(response, sizeof(response), "Image is too large: %d bytes\n", (int)request.len);
        
        char bodySizeConverted[20];
        snprintf(bodySizeConverted, sizeof(bodySizeConverted), "%lx", strlen(response));

        HttpHeader headers[3] = {
            {"Content-Type", "text/plain"},
            {"Content-Length", bodySizeConverted},
            {NULL, NULL}
        };

        unsigned char* httpResponse;
        unsigned long len;
        httpResponse = construct_HTTP_response(RESPONSE_PAYLOAD_EXCD_LIMIT, "Payload Too Large", 
                headers, (const unsigned char*)response, strlen(response), &len);
        fwrite(httpResponse, sizeof(unsigned char), len, to);
        fflush(to);
        free(httpResponse);
        return 1;
    }
    return 0;
}

int image_generation(RequestInfo request, FILE* to, SharedResources* resources) {
    char* copiedOperation = malloc(sizeof(char) * (strlen(request.address) + 1));
    strcpy(copiedOperation, request.address);
    char** splitOperation = split_by_char(copiedOperation, '/', 0);
    splitOperation++;

    FIBITMAP* targetImage = fi_load_image_from_buffer(
            (const unsigned char*)request.body, request.len);
    if (!targetImage) {
        invalid_image_check(to);
        free(copiedOperation);
        free_split_array(splitOperation);
        return 0;
    }

    int totalCommands = 0;
    while (splitOperation[totalCommands] != NULL) {
        totalCommands++;
        resources->stats.totalOperations++;
    }

    for (int i = 0; i < totalCommands; i++) {
        char** argToExecute = split_by_char(splitOperation[i], ',', 0);
        
        if (!strcmp("rotate", argToExecute[0])) {
            double angleToRotate = (double)atoi(argToExecute[1]);
            FIBITMAP* newTargetImage = FreeImage_Rotate(targetImage, angleToRotate, NULL);
            if (newTargetImage == NULL) {
                invalid_image_operation(to, "rotate");
                free_split_array(argToExecute);
                free(copiedOperation);
                free_split_array(splitOperation);
                FreeImage_Unload(targetImage);
                return 0;
            }
            FreeImage_Unload(targetImage);
            targetImage = newTargetImage;
        } else if (!strcmp("scale", argToExecute[0])) {
            FIBITMAP* newTargetImage = FreeImage_Rescale(targetImage,
                    atoi(argToExecute[1]), atoi(argToExecute[2]), FILTER_BILINEAR);
            if (newTargetImage == NULL) {
                invalid_image_operation(to, "scale");
                free_split_array(argToExecute);
                free(copiedOperation);
                free_split_array(splitOperation);
                FreeImage_Unload(targetImage);
                return 0;
            }
            FreeImage_Unload(targetImage);
            targetImage = newTargetImage;
        } else if (!strcmp("flip", argToExecute[0])) {
            if (argToExecute[1][0] == 'h') {
                if (!FreeImage_FlipHorizontal(targetImage)) {
                    invalid_image_operation(to, "flip");
                    free_split_array(argToExecute);
                    free(copiedOperation);
                    free_split_array(splitOperation);
                    FreeImage_Unload(targetImage);
                    return 0;
                }
            } else if (argToExecute[1][0] == 'v') {
                if (!FreeImage_FlipVertical(targetImage)) {
                    invalid_image_operation(to, "flip");
                    free_split_array(argToExecute);
                    free(copiedOperation);
                    free_split_array(splitOperation);
                    FreeImage_Unload(targetImage);
                    return 0;
                }
            }
        }
        
        free_split_array(argToExecute);
    }

    unsigned long newLen;
    unsigned char* convertedImage = fi_save_png_image_to_buffer(targetImage, &newLen);
    send_final_image(to, convertedImage, newLen);

    free(copiedOperation);
    free_split_array(splitOperation);
    FreeImage_Unload(targetImage);
    free(convertedImage);
    return 1;
}

// Helper function to free split arrays
void free_split_array(char** array) {
    if (array) {
        for (int i = 0; array[i] != NULL; i++) {
            free(array[i]);
        }
        free(array);
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    sem_t semlock;
    SharedResources resources = {0};
    resources.lock = &lock;
    resources.semlock = &semlock;

    ServerConfig config = parse_command_line(argc, argv);
    
    if (config.connSpecified) {
        sem_init(resources.semlock, 0, atoi(config.maxConns));
    }

    int server = establish_listening_connection(&config);
    
    // Set up signal handling
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    resources.sigSet = set;

    // Create SIGHUP handling thread
    pthread_t sighupThreadID;
    pthread_create(&sighupThreadID, NULL, sighup_thread, &resources);
    pthread_detach(sighupThreadID);

    // Accept connections and create threads
    while (1) {
        int client_fd = accept(server, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        SharedResources* thread_resources = malloc(sizeof(SharedResources));
        *thread_resources = resources;
        thread_resources->fd = client_fd;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_thread, thread_resources) != 0) {
            perror("pthread_create");
            free(thread_resources);
            close(client_fd);
        } else {
            pthread_detach(thread_id);
        }
    }

    pthread_mutex_destroy(&lock);
    return 0;
}
