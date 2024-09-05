// Import
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <csse2310a4.h>
#include <ctype.h>

// Magic nums
#define MIN_ROTATION (-359)
#define MAX_ROTATION 359
#define MAX_SCALE 10000
#define BODY_INIT_BUFFER 400
#define ARG_MIN 6
#define ARG_MAX 4
#define OK_CODE 200
#define MAX_ARGS 3

// Structs
typedef struct {
    char* portNumber;
    char* rotateDegrees;
    char* inFile;
    char* outFile;
    char* scaleArg[2];
    char flipDirection;
} ClientConditions;

typedef struct {
    char** argv;
    int argc;
    int currentArg;
} UsageCheckInfo;

typedef struct {
    int degreesArg;
    int inFileArg;
    int outFileArg;
    int scaleArg0;
    int scaleArg1;
    int flipDirectionArg;
} ArgumentPositions;

typedef struct {
    char* request;
    int numBytes;
    char* header;
    unsigned char* body;
} HTTPRequest;

typedef struct {
    int numBytes;
    unsigned char* serverBody;
    int status;
    char* statusExplanation;
} HTTPResponse;

typedef struct {
    char* name;
    char* value;
} HTTPHeader;

// Error codes
typedef enum {
    USAGE_ERROR = 12,
    READ_ERROR = 7,
    WRITE_ERROR = 1,
    CONNECTION_ERROR = 9,
    COMMUNICATION_ERROR = 18,
    RESPONSE_OUTPUT_ERROR = 13,
    HTTP_NOT_OK_ERROR = 8,
    DATA_ERROR = 2,
} ErrorCode;

// Error messages
const char* const errorUsage
        = "Usage: uqimageclient portnumber [--in infilename] [--output "
          "outputfilename] [--rotate degrees | --scale w h | --flip dirn]\n";
const char* const readError
        = "uqimageclient: unable to open file \"%s\" for reading\n";
const char* const writeError
        = "uqimageclient: unable to write to file \"%s\"\n";
const char* const connectionError
        = "uqimageclient: cannot connect to port \"%s\"\n";
const char* const noDataError = "uqimageclient: no data read for input image\n";
const char* const communicationError
        = "uqimageclient: communication error to server\n";
const char* const outputError = "uqimageclient: error while writing output\n";

// Error handlers

void error_handler_usage()
{
    fprintf(stderr, errorUsage);
    exit(USAGE_ERROR);
}

void error_handler_read(ClientConditions conditions)
{
    fprintf(stderr, readError, conditions.inFile);
    exit(READ_ERROR);
}

void error_handler_write(ClientConditions conditions)
{
    fprintf(stderr, writeError, conditions.outFile);
    exit(WRITE_ERROR);
}

void error_handler_connection(ClientConditions conditions)
{
    fprintf(stderr, connectionError, conditions.portNumber);
    exit(CONNECTION_ERROR);
}

void error_handler_no_data()
{
    fprintf(stderr, noDataError);
    exit(DATA_ERROR);
}

void error_handler_not_ok()
{
    exit(HTTP_NOT_OK_ERROR);
}

void error_handler_communication()
{
    fprintf(stderr, communicationError);
    exit(COMMUNICATION_ERROR);
}

void error_handler_output()
{
    fprintf(stderr, outputError);
    exit(RESPONSE_OUTPUT_ERROR);
}

// Helper function for usage_check to check whether the rotate arg provided by
// the user is acceptable. Takes instance of ClientConditions struct to modify
// if argument is valid. Takes instance of UsageCheckInfo struct that contains
// information about state of usage_check (loop iteration, argv and argc).
// Returns ClientConditions struct. Calls usage error handler if args are
// invalid.
ClientConditions handle_rotate_arg(
        ClientConditions conditions, UsageCheckInfo info)
{
    int convertedDegrees;
    if ((info.argc) > info.currentArg + 1) {
        if (strlen(info.argv[info.currentArg + 1]) == 0) {
            error_handler_usage();
        }
        for (int j = 1; j < (int)strlen(info.argv[info.currentArg + 1]); j++) {
            if (info.argv[info.currentArg + 1][j] == '+'
                    || info.argv[info.currentArg + 1][j] == '-') {
                error_handler_usage();
            }
        }
        for (int j = 0; j < (int)strlen(info.argv[info.currentArg + 1]); j++) {
            if ((!isalpha(info.argv[info.currentArg + 1][j]))
                    && (!isdigit(info.argv[info.currentArg + 1][j]))
                    && info.argv[info.currentArg + 1][j] != '+'
                    && info.argv[info.currentArg + 1][j] != '-') {
                error_handler_usage();
            }
        }
        convertedDegrees = atoi(info.argv[info.currentArg + 1]);
        if (!convertedDegrees) {
            error_handler_usage();
        } else if (convertedDegrees > MAX_ROTATION
                || convertedDegrees < MIN_ROTATION) {
            error_handler_usage();
        }
    } else {
        error_handler_usage();
    }
    conditions.rotateDegrees = info.argv[info.currentArg + 1];
    return conditions;
}

// Helper function for usage_check that determines whether the scale args
// provided by the user are valid. Checks if both arguments are present, if both
// args are numbers, and are within the set bounds. Takes instance of
// ClientConditions and UsageCheckInfo struct. If arguments are valid, will
// return modified ClientConditions struct, will call usage error handler if
// args are invalid.
ClientConditions handle_scale_arg(
        ClientConditions conditions, UsageCheckInfo info)
{
    if ((info.argc) > info.currentArg + 2) {
        if ((strlen(info.argv[info.currentArg + 1])) == 0
                || (strlen(info.argv[info.currentArg + 2])) == 0) {
            error_handler_usage();
        }
        for (int i = 1; i < MAX_ARGS; i++) {
            for (int j = 1; j < (int)strlen(info.argv[info.currentArg + i]);
                    j++) {
                if (info.argv[info.currentArg + i][j] == '+'
                        || info.argv[info.currentArg + i][j] == '-') {
                    error_handler_usage();
                }
            }
            // Check if it's a symbol that is not - or +
            for (int j = 0; j < (int)strlen(info.argv[info.currentArg + i]);
                    j++) {
                if ((!isalpha(info.argv[info.currentArg + i][j]))
                        && (!isdigit(info.argv[info.currentArg + i][j]))
                        && info.argv[info.currentArg + i][j] != '+'
                        && info.argv[info.currentArg + i][j] != '-') {
                    error_handler_usage();
                }
            }
            int convertedScaleArgument = atoi(info.argv[info.currentArg + i]);
            if (!convertedScaleArgument) {
                fflush(stdout);
                error_handler_usage();
            }
            if (convertedScaleArgument < 1
                    || convertedScaleArgument > MAX_SCALE) {
                fflush(stdout);
                error_handler_usage();
            }

            char* tempString = info.argv[info.currentArg + i];
            conditions.scaleArg[i - 1] = tempString;
        }
    } else {
        error_handler_usage();
    }
    return conditions;
}

// Helper function for usage_check to determine if the flip args provided by the
// user are valid. If arg is not 'h' or 'v', will call usage error handler.
// Modifies and returns modified ClientConditions struct if args are valid, will
// call error_handler_usage() otherwise. Takes ClientConditions and
// UsageCheckInfo structs.
ClientConditions handle_flip_arg(
        ClientConditions conditions, UsageCheckInfo info)
{
    if ((info.argc) > info.currentArg + 1) {
        if ((strlen(info.argv[info.currentArg + 1]) == 0)) {
            error_handler_usage();
        }
        if (strcmp(info.argv[info.currentArg + 1], "h")
                && (strcmp(info.argv[info.currentArg + 1], "v"))) {
            error_handler_usage();
        }
        conditions.flipDirection = info.argv[info.currentArg + 1][0];
    } else {
        error_handler_usage();
    }
    return conditions;
}

// Helper function for usage_check to determine whether the in and output files
// specified by the user are valid. Validation process same for either file, so
// fileType is specified so correct file is stored in the ClientConditions
// struct. Takes ClientConditions struct and UsageCheckInfo struct. Returns
// modified ClientConditions struct. Calls error_handler _usage if arg(s)
// invalid.
ClientConditions handle_io_arg(
        ClientConditions conditions, UsageCheckInfo info, int fileType)
{
    if ((info.argc) > info.currentArg + 1) {
        if (strlen(info.argv[info.currentArg + 1]) != 0) {
            if (fileType) {
                conditions.inFile = info.argv[info.currentArg + 1];
            } else {
                conditions.outFile = info.argv[info.currentArg + 1];
            }
        } else {
            error_handler_usage();
        }
    } else {
        error_handler_usage();
    }

    return conditions;
}

// Helper function for usage check to handle the port argument. Only need to
// check that it's non-empty. Takes port specified by user as arg as well as
// ClientConditions struct. Returns modified struct.
ClientConditions handle_port_arg(ClientConditions conditions, char* port)
{
    if (strlen(port) == 0) {
        error_handler_usage();
    }
    conditions.portNumber = port;
    return conditions;
}

// Checks that the input that the user specified can be read from. Checks
// that the output file that the user specified can be written to. Takes
// ClientConditions struct (where filenames are stored) and returns nothing,
// but will call error handlers that will terminate the program if
// one or more of the files are unopenable.
void validity_check_io(ClientConditions conditions)
{
    if (conditions.inFile) {
        int readfd = open(conditions.inFile, O_RDONLY);
        if (readfd < 0) {
            error_handler_read(conditions);
        }
        close(readfd);
    }
    if (conditions.outFile) {
        int writefd = open(conditions.outFile, O_RDWR | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR);
        if (writefd < 0) {
            error_handler_write(conditions);
        }
        close(writefd);
    }
}

// Check if the arguments provided by user are valid by checking if argc > 0,
// checking argv by using various helper functions. Checks for duplicates and
// unexpected option arguments. Assigns values to the ClientConditions struct
// which is returned if no usage errors are detected.
ClientConditions check_usage(int argc, char** argv)
{
    ClientConditions conditions = {0, 0, NULL, NULL, {0, 0}, 0};
    UsageCheckInfo info = {NULL, 0, 0};
    ArgumentPositions positions = {0, 0, 0, 0, 0, 0};
    argv++;
    argc--;
    int argSet = 0;
    int scaleFlag = 0;
    info.argv = argv;
    info.argc = argc;
    // Increment argv by one and decrement argc by one to ignore filename
    if (argc) {
        for (int i = 0; i < argc; i++) { // If one of the positions of the args,
            // don't check if its a valid argument
            info.currentArg = i;
            if ((i == positions.inFileArg || i == positions.degreesArg
                        || i == positions.outFileArg || i == positions.scaleArg0
                        || i == positions.flipDirectionArg
                        || i == positions.scaleArg1)
                    && i != 0) {
                continue;
            }
            if (i == 0) {
                conditions = handle_port_arg(conditions, argv[i]);
                continue;
            }
            if (!strcmp("--in", argv[i]) && !conditions.inFile) {
                conditions = handle_io_arg(conditions, info, 1);
                positions.inFileArg = i + 1;

            } else if (!strcmp("--output", argv[i]) && !conditions.outFile) {
                conditions = handle_io_arg(conditions, info, 0);
                positions.outFileArg = i + 1;

            } else if (!strcmp("--rotate", argv[i])
                    && !conditions.rotateDegrees) {
                if (argSet) {
                    error_handler_usage();
                }
                conditions = handle_rotate_arg(conditions, info);
                positions.degreesArg = i + 1;
                argSet = 1;

            } else if (!strcmp("--flip", argv[i])
                    && !conditions.flipDirection) {
                if (argSet) {
                    error_handler_usage();
                }

                conditions = handle_flip_arg(conditions, info);
                positions.flipDirectionArg = i + 1;
                argSet = 1;

            } else if (!strcmp("--scale", argv[i]) && !scaleFlag) {
                if (argSet) {
                    error_handler_usage();
                }
                // Set flags so we don't get repeated args
                scaleFlag = 1;
                conditions = handle_scale_arg(conditions, info);
                positions.scaleArg0 = i + 1;
                positions.scaleArg1 = i + 2;
                argSet = 1;
            } else {
                error_handler_usage();
            }
        }
    } else {
        error_handler_usage();
    }
    return conditions;
}

// Attempt to resolve an address and then establish a connection to localhost
// with the provided port number. If we're unable to get the address or
// establish a connection to the server with the provided port no., then
// call the connection error handler. Takes ClientConditions struct to extract
// port number and returns socket file descriptor.
int establish_connection(ClientConditions conditions)
{
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err;
    if ((err = getaddrinfo("localhost", conditions.portNumber, &hints, &ai))) {
        freeaddrinfo(ai);
        error_handler_connection(conditions);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, ai->ai_addr, sizeof(struct sockaddr))) {
        error_handler_connection(conditions);
    }
    return fd;
}

// Reads input from specified source. Will read file if --in specified by user,
// otherwise will read from stdin. Bytes are then fed into HTTPRequest struct
// where they are stored in an unsigned char* and ready to be packaged into
// HTTP request. Number of bytes retrieved from file is also counted
// and then recorded in the HTTPRequest struct. Returns HTTP struct,
// takes ClientConditions struct.
HTTPRequest handle_input(ClientConditions conditions)
{
    HTTPRequest request = {NULL, 0, NULL, NULL};
    request.numBytes = 0;
    int bytesSent = 0;
    int byte = 0;
    int buffer = BODY_INIT_BUFFER;
    unsigned char* httpBody = malloc(sizeof(unsigned char) * buffer);
    if (conditions.inFile) {
        FILE* fileInFd = fopen(conditions.inFile, "r");
        while (!feof(fileInFd)) {
            if (bytesSent == buffer - 2) {
                buffer *= 2;
                httpBody = realloc(httpBody, sizeof(unsigned char) * buffer);
            }
            byte = fgetc(fileInFd);
            httpBody[bytesSent++] = (unsigned char)byte;
            if (byte == EOF) {
                bytesSent--;
            }
        }
        fclose(fileInFd);
        if (!bytesSent) {
            error_handler_no_data();
        }
        // If infile not specified, read from stdin
    } else {
        while (!feof(stdin)) {
            if (bytesSent == buffer - 1) {
                buffer *= 2;
                httpBody = realloc(httpBody, sizeof(unsigned char) * buffer);
            }
            byte = fgetc(stdin);
            httpBody[bytesSent++] = (unsigned char)byte;
            if (byte == EOF) {
                bytesSent--;
            }
        }
        if (!bytesSent) {
            error_handler_no_data();
        }
    }
    request.numBytes = bytesSent;
    request.body = httpBody;
    return request;
}

// Function responsible for assembling the flip argument that
// is to be packaged into the request. Returns char* in form
// of the final argument and takes an instance of the Client
// Conditions struct to extract the flip argument.
char* assemble_flip_arg(ClientConditions conditions)
{
    char* flipArg = malloc(sizeof(char) * ARG_MIN + ARG_MAX);
    strcpy(flipArg, "flip");
    strcat(flipArg, ",");
    char flipArg0[2];
    flipArg0[0] = conditions.flipDirection;
    flipArg0[1] = '\0';
    strcat(flipArg, flipArg0);
    return flipArg;
}

// Function responsible for assembling the scale argument
// that is to be packaged into the HTTP request. Returns char*
// in form of the final argument and takes an instance of the
// ClientConditions struct to extract scale arg.
char* assemble_scale_arg(ClientConditions conditions)
{
    char* scaleArg = malloc(sizeof(char) * ARG_MIN + ARG_MAX);
    strcpy(scaleArg, "scale");
    strcat(scaleArg, ",");
    strcat(scaleArg, conditions.scaleArg[0]);
    strcat(scaleArg, ",");
    strcat(scaleArg, conditions.scaleArg[1]);
    return scaleArg;
}

// Function responsible for assembling the rotate arg that is to be
// packaged into the HTTP request. Returns char* in the form of the final
// argument and takes an instance of the ClientConditions struct to
// extract the assemble arg.
char* assemble_rotate_arg(ClientConditions conditions, int genericArg)
{
    char* rotateArg = malloc(sizeof(char) * ARG_MIN + ARG_MAX);
    strcpy(rotateArg, "rotate");
    strcat(rotateArg, ",");
    if (!genericArg) {
        strcat(rotateArg, conditions.rotateDegrees);
    } else {
        strcat(rotateArg, "0");
    }
    return rotateArg;
}

// Assembles the address to be packaged into the request
// by taking the final versions of the assemble,
// flip and rotate args and combining them to
// create a valid address request. Returns char* in form of final
// address. Takes ClientConditions struct.
char* assemble_address(ClientConditions conditions)
{
    char* rotateString;
    char* scaleArg;
    char* flipArg;
    char* address = malloc(sizeof(char) * BODY_INIT_BUFFER);
    strcpy(address, "/");
    int rotateFlag = 0;
    int scaleFlag = 0;
    int flipFlag = 0;
    if (conditions.rotateDegrees) {
        rotateString = assemble_rotate_arg(conditions, 0);
        rotateFlag = 1;
    } else if (conditions.scaleArg[0]) {
        scaleArg = assemble_scale_arg(conditions);
        scaleFlag = 1;
    } else if (conditions.flipDirection) {
        flipArg = assemble_flip_arg(conditions);
        flipFlag = 1;
    }
    if (rotateFlag) {
        strcat(address, rotateString);
    }
    if (scaleFlag) {
        strcat(address, scaleArg);
    }
    if (flipFlag) {
        strcat(address, flipArg);
    }
    if (!flipFlag && !scaleFlag && !rotateFlag) {
        char* rotateString = assemble_rotate_arg(conditions, 1);
        strcat(address, rotateString);
    }
    return address;
}

// Responsible for receiving HTTP responses from the server and
// storing it into a HTTPResponse struct. Returns the struct,
// takes read end of the file descriptor and takes an instance
// of the HTTPResponse struct that is ready to be populated.
HTTPResponse handle_server_input(int fd2, HTTPResponse response)
{
    unsigned char* body;
    unsigned long len;
    HttpHeader** headers;
    int status;
    char* statusExplanation;
    FILE* from = fdopen(fd2, "r");
    if (get_HTTP_response(
                from, &status, &statusExplanation, &headers, &body, &len)) {
    } else {
        error_handler_communication();
    }
    fclose(from);
    response.serverBody = body;
    response.numBytes = (int)len;
    response.status = status;
    response.statusExplanation = statusExplanation;
    return response;
}

// Takes response from server and responds appropriately depending
// on what was sent by the server. Returns nothing, takes read end
// of the file descriptor and an instance of the ClientConditions
// struct.
void http_receive_response(ClientConditions conditions, int fd2)
{
    HTTPResponse response = {0, NULL, 0, NULL};
    response = handle_server_input(fd2, response);
    if (response.status == OK_CODE) {
        if (conditions.outFile) {
            size_t bytesWritten;
            FILE* fileout = fopen(conditions.outFile, "w");
            bytesWritten = fwrite(response.serverBody, sizeof(unsigned char),
                    response.numBytes, fileout);
            if ((int)bytesWritten < response.numBytes) {
                error_handler_output();
            }
            fclose(fileout);
        } else {
            size_t bytesWritten;
            bytesWritten = fwrite(response.serverBody, sizeof(unsigned char),
                    response.numBytes, stdout);
            if ((int)bytesWritten < response.numBytes) {
                error_handler_output();
            }
        }
    } else {
        size_t bytesWritten;
        bytesWritten = fwrite(response.serverBody, sizeof(unsigned char),
                response.numBytes, stderr);
        if ((int)bytesWritten < response.numBytes) {
            error_handler_output();
        }
        error_handler_not_ok();
    }
}

// Responsible for building a request to be sent to the server and then
// writing that request through the write end of the fd. Takes HTTPRequest
// struct, extracts elements of the struct and assembles a final
// request from the elements, sends request. Calls http_receive_response
// to receive response after request sent. Takes write end of the fd,
// ClientConditions struct and HTTPrequest request.
void http_request_constructor(
        ClientConditions conditions, HTTPRequest request, int fd)
{
    char contentLength[BODY_INIT_BUFFER];
    sprintf(contentLength, "%d", request.numBytes);
    int fd2 = dup(fd);
    FILE* to = fdopen(fd, "w");
    char* finalRequest
            = malloc(sizeof(char) * request.numBytes + BODY_INIT_BUFFER);
    strcpy(finalRequest, "POST ");
    char* address = assemble_address(conditions);
    strcat(finalRequest, address);
    strcat(finalRequest, " ");
    strcat(finalRequest, "HTTP/1.1\r\n");
    strcat(finalRequest, "Content-Length: ");
    strcat(finalRequest, contentLength);
    strcat(finalRequest, "\r\n");
    strcat(finalRequest, "\r\n");
    fwrite(finalRequest, sizeof(char), strlen(finalRequest), to);
    fwrite(request.body, sizeof(unsigned char), request.numBytes, to);
    fclose(to);
    http_receive_response(conditions, fd2);
}

int main(int argc, char** argv)
{
    ClientConditions conditions = check_usage(argc, argv);
    validity_check_io(conditions);
    int fd = establish_connection(conditions);
    HTTPRequest request = handle_input(conditions);
    http_request_constructor(conditions, request, fd);
    fflush(stdout);
}
