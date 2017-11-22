/*
UNIX honeypot daemon
Andrey Voloshin andrey@voloshin.work 2017

To compile: gcc -o honeypotd honeypotd.c
To run:     sudo ./honeypotd
To test daemon: ps -ef|grep honeypotd (or ps -aux on BSD systems)
To test log:    grep honeypotd /var/log/syslog
To test signal: kill -HUP `cat /tmp/honeypotd.lock`
To terminate:   kill `cat /tmp/honeypotd.lock`
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

#define RUNNING_DIR    "/tmp"
#define LOCK_FILE    "honeypotd.lock"
#define SOCKET_PORT 21

void signal_handler(sig)
        int sig;
{
    switch (sig) {
        case SIGHUP:
            syslog(LOG_NOTICE, "hangup signal catched");
            break;
        case SIGTERM:
            syslog(LOG_NOTICE, "terminate signal catched");
            exit(0);
            break;
    }
}

void block_faggot(struct in_addr ipAddr) {
    char ipStr[INET_ADDRSTRLEN];
    char cmd[300];

    inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);

    sprintf(cmd, "iptables -A INPUT -s %s -j DROP", ipStr);
    syslog(LOG_WARNING, "Command executed: %s\r\n", cmd);
    system(cmd);
}

void create_honeypot(void (*fn_block)(struct in_addr)) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t clientlen = sizeof(client_addr);
    int reuse;
    int server, client;

    // setup socket address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SOCKET_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // create socket
    server = socket(PF_INET, SOCK_STREAM, 0);
    if (!server) {
        perror("socket");
        exit(-1);
    }

    // set socket to immediately reuse port when the application closes
    reuse = 1;
    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        exit(-1);
    }

    // call bind to associate the socket with our local address and
    // port
    if (bind(server, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(-1);
    }

    // convert the socket to listen for incoming connections
    if (listen(server, SOMAXCONN) < 0) {
        perror("listen");
        exit(-1);
    }

    // accept clients
    syslog(LOG_NOTICE, "Waiting for faggots on port %d\r\n", SOCKET_PORT);
    while ((client = accept(server, (struct sockaddr *) &client_addr, &clientlen)) > 0) {
        block_faggot(client_addr.sin_addr);
        close(client);
    }

    close(server);
}

void daemonize() {
    int i, lfp;
    char str[10];
    if (getppid() == 1) return; /* already a daemon */
    i = fork();
    if (i < 0) exit(1); /* fork error */
    if (i > 0) exit(0); /* parent exits */
    /* child (daemon) continues */
    setsid(); /* obtain a new process group */
    for (i = getdtablesize(); i >= 0; --i) close(i); /* close all descriptors */
    i = open("/dev/null", O_RDWR);
    dup(i);
    dup(i); /* handle standart I/O */
    umask(027); /* set newly created file permissions */
    chdir(RUNNING_DIR); /* change running directory */
    lfp = open(LOCK_FILE, O_RDWR | O_CREAT, 0640);
    if (lfp < 0) exit(1); /* can not open */
    if (lockf(lfp, F_TLOCK, 0) < 0) exit(0); /* can not lock */
    /* first instance continues */
    sprintf(str, "%d\n", getpid());
    write(lfp, str, strlen(str)); /* record pid to lockfile */
    signal(SIGCHLD, SIG_IGN); /* ignore child */
    signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGHUP, signal_handler); /* catch hangup signal */
    signal(SIGTERM, signal_handler); /* catch kill signal */

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

int main() {

    daemonize();

    openlog("honeypotd", LOG_PID, LOG_DAEMON);

    syslog(LOG_NOTICE, "honeypotd started.");

    create_honeypot(block_faggot);

    syslog(LOG_NOTICE, "honeypotd terminated.");
    closelog();

    return EXIT_SUCCESS;
}
