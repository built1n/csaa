#include "service_provider.h"
#include "test.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int bind_unix_socket(const char *fname)
{
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fname, sizeof(addr.sun_path) - 1);
    if(bind(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
        return -1;

    return sockfd;
}

static const char *cleanup_socket = NULL;
void cleanup(void)
{
    if(cleanup_socket)
        unlink(cleanup_socket);
}

void signal_handler(int sig)
{
    cleanup();
    exit(1);
}

void run_tests(void)
{
    crypto_test();
    tm_test();
    sp_test();
}

int main()
{
    //run_tests();

    const char *socket_name = "socket";
    int sockfd;
    if((sockfd = bind_unix_socket(socket_name)) < 0)
    {
        perror("bind");
        return 1;
    }

    printf("Listening on '%s'\n", socket_name);

    cleanup_socket = socket_name;

    atexit(cleanup);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    sp_main(sockfd);
}
