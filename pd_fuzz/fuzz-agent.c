/* PicoTCP Test application */
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_dev_tap.h"
#include "pico_nat.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_dev_loop.h"
#include "pico_dhcp_client.h"
#include "pico_dhcp_server.h"
#include "pico_ipfilter.h"
#include "pico_olsr.h"
#include "pico_sntp_client.h"
#include "pico_mdns.h"
#include "pico_tftp.h"
#include "pico_dev_radiotest.h"
#include "pico_dev_radio_mgr.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#ifdef FAULTY
#include "pico_faulty.h"
#endif

/* Socket includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/* Fuzz Agent includes */
#include "PacketDrillHandlerTask.h"
#include <pthread.h>

void app_tcpecho(char *args);

struct pico_ip4 ZERO_IP4 = {
    0
};
struct pico_ip_mreq ZERO_MREQ = {
    .mcast_group_addr = {{0}},
    .mcast_link_addr  = {{0}}
};
struct pico_ip_mreq_source ZERO_MREQ_SRC = {
    .mcast_group_addr.ip4  = {0},
    .mcast_link_addr.ip4   = {0},
    .mcast_source_addr.ip4 = {0}
};
struct pico_ip6 ZERO_IP6 = {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
struct pico_ip_mreq ZERO_MREQ_IP6 = {
    .mcast_group_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_link_addr.ip6  = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}
};
struct pico_ip_mreq_source ZERO_MREQ_SRC_IP6 = {
    .mcast_group_addr.ip6 =  {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_link_addr.ip6 =   {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_source_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}
};

/* #define INFINITE_TCPTEST */
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */

/* #define PICOAPP_IPFILTER 1 */

int IPV6_MODE = 1;
static int flag = 0;
#define BSIZE (1024 * 10)
static char recvbuf[BSIZE];
static int pos = 0, len = 0;

const time_t xMaxMSToWait = 500000;
struct event * pvAcceptEvent = NULL;
struct event * pvReadEvent = NULL;

struct pico_ip4 inaddr_any = {
    0
};
struct pico_ip6 inaddr6_any = {{0}};

void deferred_exit(pico_time __attribute__((unused)) now, void *arg)
{
    if (arg) {
        free(arg);
        arg = NULL;
    }

    printf("%s: quitting\n", __FUNCTION__);
    exit(0);
}



/** From now on, parsing the command line **/
#define NXT_MAC(x) ++ x[5]

static void __wakeup(uint16_t __attribute__((unused)) ev, struct pico_socket __attribute__((unused)) *s)
{

}

int send_tcpecho(struct pico_socket *s)
{
    int w, ww = 0;
    if (len > pos) {
        do {
            w = pico_socket_write(s, recvbuf + pos, len - pos);
            if (w > 0) {
                pos += w;
                ww += w;
                if (pos >= len) {
                    pos = 0;
                    len = 0;
                }
            }
        } while((w > 0) && (pos < len));
    }

    return ww;
}

static void *picoTcpLoopThread(void *param) {

#ifdef PICO_SUPPORT_MM
    pico_mem_init(128 * 1024);
#endif

#ifdef FAULTY
    atexit(memory_stats);
#endif

    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}

void close_fuzz_socket(struct pico_socket *sock) {

    // pico_socket_del(sock);

    for (int counter = 3; counter < socketCounter; counter++) {
        struct ContikiSocket xSocket = socketArray[counter];
        if (xSocket.initialized == SOCKET_TCP && xSocket.tcp_conn == sock) {
            memset(socketArray + counter, 0, sizeof(struct ContikiSocket));
            
        } 
    }

}

void fuzz_agent_cb(uint16_t ev, struct pico_socket *s)
{
    int r = 0;

    picoapp_dbg("tcpecho> wakeup ev=%u\n", ev);

    if (ev & PICO_SOCK_EV_RD) {
        if (flag & PICO_SOCK_EV_CLOSE)
            printf("SOCKET> EV_RD, FIN RECEIVED\n");

        // printf("Received PICO_SOCK_EV_RD signal...\n");
        ecData.pending_data = 1;
        ecData.event = PICO_SOCK_EV_RD;
        ecData.sock = s;
        event_signal(pvReadEvent);
    }

    if (ev & PICO_SOCK_EV_CONN) {
        // TODO: Send signal to main thread
        printf("Received PICO_SOCK_EV_CONN signal...\n");
        acceptEventData.pending_data = 1;
        acceptEventData.event = PICO_SOCK_EV_CONN;
        acceptEventData.sock = s;
        event_signal(pvAcceptEvent);
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("Socket %p closed. \n", s);
        close_fuzz_socket(s);
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("Socket error received: %s. \n", strerror(pico_err));
        
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("Socket received close from peer.\n");
        if (flag & PICO_SOCK_EV_RD) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("SOCKET> Called shutdown write, ev = %d\n", ev);
        }
    }

    if (ev & PICO_SOCK_EV_WR) {
        // printf("Received PICO_SOCK_EV_WR signal...\n");
    }
}




char *getSocketName() {
    char *socket_name;

    const char *interface_name = getenv("TAP_INTERFACE_NAME");

    if (interface_name != NULL) {
        
        int len = strlen(interface_name) + strlen("/tmp/socket-") + 1;
        socket_name = malloc(len * sizeof(char));
        snprintf(socket_name, len, "/tmp/socket-%s", interface_name);
    } else {
        socket_name = strdup("/tmp/socket-default");
    }

    return socket_name;
}


int main(int argc, char **argv)
{

    pico_stack_init();

    pvAcceptEvent = event_create();
    pvReadEvent = event_create();

    struct pico_device *dev = NULL;
    struct pico_ip4 addr4 = {
        0
    };
    struct pico_ip4 bcastAddr = ZERO_IP4;

    struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;

    static struct SyscallResponsePackage syscallResponse;
    static struct SyscallPackage syscallPackage;
    static int sfd, cfd;
    int yes = 1;

    dev = pico_tap_create();
    if (!dev) {
        perror("Creating tap");
        exit(1);
    }

    pico_string_to_ipv4("192.168.5.4", &ipaddr.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask.addr);
    pico_ipv4_link_add(dev, ipaddr, netmask);
    bcastAddr.addr = (ipaddr.addr) | (~netmask.addr);

    printf("Testing this gets called 1...\n");
#ifdef PICO_SUPPORT_IPV6
    if (IPV6_MODE) {
        printf("Testing this gets called 2...\n");
        struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}}, gateway6 = {{0}}, zero6 = {{0}};
        pico_string_to_ipv6("fb00::302:304:506:708", ipaddr6.addr);
        pico_string_to_ipv6("fb00::302:304:506:0", netmask6.addr);
        pico_ipv6_link_add(dev, ipaddr6, netmask6);
        

        pico_ipv6_dev_routing_enable(dev);
    }

#endif  /* PICO_SUPPORT_IPV6 */

    pthread_t picoTcpLoopThreadHandle;
    int threadRet = pthread_create( &picoTcpLoopThreadHandle,
                            NULL,
                            picoTcpLoopThread,
                            NULL );

    printf("PacketDrill Bridge Thread started...\n");

    struct sockaddr_un addr;

    char *socket_name = getSocketName();

    unlink(socket_name);

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sfd == -1) {
        printf("Error creating socket...\n");
        return -1;
    }

    // Zero out the address, and set family and path.
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_name);
    free(socket_name);

    if (bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
        printf("Error binding socket to port...\n");
        return -1;
    }

    if (listen(sfd, BACKLOG) ==-1) {
        printf("Error listening on socket...\n");
        return -1;
    }

    for (;;) {

    #ifdef __AFL_HAVE_MANUAL_CONTROL

    while (__AFL_LOOP(1000)) {

    #endif

    printf("Waiting to accept a connection...\n");

    cfd = accept(sfd, NULL, NULL); // Suppressed -Werror=maybe-uninitialized on sfd

    if (cfd == -1) {
        printf("Error accepting connection...\n");
        return -1;
    }

    printf("accept returned with cfd %d...\n", cfd);

    //
    // Transfer data from connected socket to stdout until EOF 
    //

    ssize_t numRead;

    while ((numRead = read(cfd, &syscallPackage, sizeof(struct SyscallPackage))) > 0) {

        if (syscallPackage.bufferedMessage == 1) {
            void *buffer = malloc(syscallPackage.bufferedCount);
            ssize_t bufferCount = read(cfd, buffer, syscallPackage.bufferedCount);

            if (bufferCount <= 0) {
                printf("Error reading buffer content from socket\n");
            } else if (bufferCount != syscallPackage.bufferedCount) {
                printf("Count of buffer not equal to expected count.\n");
            } else {
                printf("Successfully read buffer count from socket.\n");
            }

            syscallPackage.buffer = buffer;

        }

        printf("Packetdrill command received: %s\n", syscallPackage.syscallId);

        int response = -1;

        if (strcmp(syscallPackage.syscallId, "socket_create") == 0) {
            /* Create a TCP socket. */

            struct SocketPackage socketPackage = syscallPackage.socketPackage;

            struct ContikiSocket xSocket;
            
            // TODO: Make the IP version and protocol configurable
            int ipVersion = socketPackage.domain == AF_INET ? PICO_PROTO_IPV4 : PICO_PROTO_IPV6;
            int protocol = socketPackage.type = SOCK_STREAM ? PICO_PROTO_TCP : PICO_PROTO_UDP;
            struct pico_socket *tcp_socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &fuzz_agent_cb);
            printf("Socket %p opened...\n", tcp_socket);

            if (tcp_socket != NULL) {
                pico_socket_setoption(tcp_socket, PICO_TCP_NODELAY, &yes);

                xSocket.tcp_conn = tcp_socket;
                xSocket.initialized = SOCKET_TCP;

                // TODO: Check for array out of bounds access
                socketArray[socketCounter] = xSocket;

                response = socketCounter;
                socketCounter++;
            } else {
                printf("Error creating socket...\n");
            }

            syscallResponse.result = response;

        } else if (strcmp(syscallPackage.syscallId, "socket_bind") == 0) {

            struct BindPackage bindPackage = syscallPackage.bindPackage;

            struct ContikiSocket xSocket = socketArray[bindPackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            union {
                struct pico_ip4 ip4;
                struct pico_ip6 ip6;
            } inaddr_any = {
                .ip4 = {0}, .ip6 = {{0}}
            };

            uint16_t listenPort = 0;
            if (IPV6_MODE) {
                struct sockaddr_in6 *sock_addr6 = (struct sockaddr_in6 *) &bindPackage.addr6;
                listenPort = sock_addr6->sin6_port;
                response = pico_socket_bind(xSocket.tcp_conn, &inaddr_any.ip6, &listenPort);
            } else {
                struct sockaddr_in *sock_addr = (struct sockaddr_in *) &bindPackage.addr;
                listenPort = sock_addr->sin_port;
                response = pico_socket_bind(xSocket.tcp_conn, &inaddr_any.ip4, &listenPort);
            }

            if (response == 0) {
                printf("Binding to port %d...\n", short_be(listenPort));
            }

            syscallResponse.result = response;

        } else if (strcmp(syscallPackage.syscallId, "socket_listen") == 0) {

            struct ListenPackage listenPackage = syscallPackage.listenPackage;

            struct ContikiSocket xSocket = socketArray[listenPackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            response = pico_socket_listen(xSocket.tcp_conn, 40);

            if (response < 0) {
                printf("Error listening on socket with response: %d\n", response);
                goto returnResult;
            }

            syscallResponse.result = response;

        } else if (strcmp(syscallPackage.syscallId, "socket_accept") == 0) {

            //struct AcceptPackage acceptPackage = syscallPackage.acceptPackage;
            // TODO: Ensure sockfd exists and matches the connection that was established

            struct AcceptPackage acceptPackage = syscallPackage.acceptPackage;

            struct ContikiSocket xSocket = socketArray[acceptPackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            if (acceptEventData.pending_data != 1 || acceptEventData.event != PICO_SOCK_EV_CONN) { // Socket hasn't connected yet
                printf("About to yield in accept...\n");
                event_wait_timed(pvAcceptEvent, xMaxMSToWait);
            }

            printf("Waking up from yield...\n");

            if (acceptEventData.event == PICO_SOCK_EV_CONN) {

                uint32_t ka_val = 0;
                int ipAddrLen = IPV6_MODE ? sizeof (struct pico_ip6) : sizeof (struct pico_ip6);
                void *orig = PICO_ZALLOC(ipAddrLen);
                uint16_t port = 0;
                char peer[30];
                int yes = 1;

                struct pico_socket *sock_a = pico_socket_accept(xSocket.tcp_conn, orig, &port);

                printf("Socket %p accepted...\n", sock_a);

                // pico_ipv4_to_string(peer, orig.addr);
                // printf("Connection established with %s:%d.\n", peer, short_be(port));

                pico_socket_setoption(sock_a, PICO_TCP_NODELAY, &yes);
                /* Set keepalive options */
                ka_val = 5;
                pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPCNT, &ka_val);
                ka_val = 30000;
                pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPIDLE, &ka_val);
                ka_val = 5000;
                pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPINTVL, &ka_val);

                struct ContikiSocket connSocket;
                connSocket.initialized = SOCKET_TCP;
                connSocket.tcp_conn = sock_a;
                socketArray[socketCounter] = connSocket;

                response = socketCounter;
                socketCounter++;

                struct AcceptResponsePackage acceptResponse;
                    
                if (IPV6_MODE) {
                    pico_ipv4_to_string(peer, ((struct pico_ip6 *) orig)->addr);
                    printf("Connection established with %s:%d.\n", peer, short_be(port));

                    struct sockaddr_in6 addr;
                    addr.sin6_family = AF_INET6;
                    addr.sin6_port = port;
                    memcpy(&addr.sin6_addr.s6_addr, orig, sizeof (struct pico_ip6));

                    acceptResponse.addr6 = addr;
                    acceptResponse.addrlen = sizeof(struct sockaddr_in6);
                } else {
                    pico_ipv4_to_string(peer, ((struct pico_ip4 *) orig)->addr);
                    printf("Connection established with %s:%d.\n", peer, short_be(port));

                    struct sockaddr_in addr;
                    addr.sin_family = AF_INET;
                    addr.sin_port = port;
                    memcpy(&addr.sin_addr.s_addr, orig, sizeof(struct pico_ip4));

                    acceptResponse.addr = addr;
                    acceptResponse.addrlen = sizeof(struct sockaddr_in);
                }

                syscallResponse.result = response;
                syscallResponse.acceptResponse = acceptResponse;

                memset(&acceptEventData, 0, sizeof(struct EventCallbackData));
            } else {
                syscallResponse.result = -1;
            }

        } else if (strcmp(syscallPackage.syscallId, "socket_connect") == 0) {

            // struct BindPackage connectPackage = syscallPackage.connectPackage;

            // struct ContikiSocket xSocket = socketArray[connectPackage.sockfd];

            // int connectResult = -1;
            // if (xSocket.initialized == SOCKET_TCP) {
            //     uip_ipaddr_t dest_ipaddr;
            //     memcpy(dest_ipaddr.u8, &connectPackage.addr6.sin6_addr, 16);

            //     connectResult = tcp_socket_connect(xSocket.tcp_conn, &dest_ipaddr, uip_htons(connectPackage.addr6.sin6_port));
            // }

            // if (connectResult < 0) {
            //     printf("Error connecting to socket with response: %d\n", connectResult);
            //     syscallResponse.result = -1;
            // } else {
            //     PROCESS_WAIT_EVENT();
            //     printf("Successfully connected to socket\n");
            //     syscallResponse.result = 0;
            // }

            
        } else if (strcmp(syscallPackage.syscallId, "socket_write") == 0) {

            struct WritePackage writePackage = syscallPackage.writePackage;

            struct ContikiSocket xSocket = socketArray[writePackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            response = pico_socket_write(xSocket.tcp_conn, syscallPackage.buffer, syscallPackage.bufferedCount); 

            if (response <= 0) {
                printf("Error writing to socket with response: %d\n", response);
            } 
            
        } else if (strcmp(syscallPackage.syscallId, "socket_sendto") == 0) {

            // struct SendToPackage sendtoPackage = syscallPackage.sendToPackage; // Suppressed -Werror=maybe-uninitialized

            // struct ContikiSocket xSocket = socketArray[sendtoPackage.sockfd];

            // int writeResult = 0;
            
            // if ( xSocket.initialized == SOCKET_UDP) {
                
            //     uip_ipaddr_t dest_ipaddr;
            //     memcpy(dest_ipaddr.u8, &sendtoPackage.addr6.sin6_addr, 16);

            //     simple_udp_sendto_port(xSocket.udp_conn, syscallPackage.buffer, syscallPackage.bufferedCount, 
            //     &dest_ipaddr, uip_ntohs(sendtoPackage.addr6.sin6_port));

            //     writeResult = syscallPackage.bufferedCount;

            // }

            // syscallResponse.result = writeResult;
        } else if (strcmp(syscallPackage.syscallId, "socket_read") == 0) {

            struct ReadPackage readPackage = syscallPackage.readPackage;
            struct ContikiSocket xSocket = socketArray[readPackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            if (ecData.pending_data != 1 || ecData.event != PICO_SOCK_EV_RD) { // Socket hasn't connected yet
                printf("About to yield in read...\n");
                event_wait_timed(pvReadEvent, xMaxMSToWait);
            }

            printf("Just woke up from yielding with data: %d and event: %d...\n", ecData.pending_data, ecData.event);

            if (ecData.pending_data == 1 && ecData.event == PICO_SOCK_EV_RD) {

                char recvbuf[BSIZE];

                response = pico_socket_read(xSocket.tcp_conn, recvbuf, readPackage.count);
            } 

        } else if (strcmp(syscallPackage.syscallId, "socket_recvfrom") == 0) {

            // if (rxData.pending_data != 1) {
            //     printf("About to yield...\n");
            //     PROCESS_WAIT_EVENT();
            // }

            // printf("Just woke up from yielding...\n");


            // if (rxData.pending_data == 1) {
            //     struct sockaddr_in6 addr;
            //     addr.sin6_port = rxData.sender_port;
            //     addr.sin6_addr = rxData.sender_addr;

            //     struct AcceptResponsePackage acceptResponse;
            //     acceptResponse.addr6 = addr;
            //     acceptResponse.addrlen = sizeof(struct sockaddr_in6);

            //     syscallResponse.result = rxData.datalen;
            //     syscallResponse.acceptResponse = acceptResponse; // Suppressed -Werror=maybe-uninitialized
            //     rxData.pending_data = 0;
            // } else {
            //     syscallResponse.result = 0;
            // }

            

        } else if (strcmp(syscallPackage.syscallId, "socket_close") == 0){

            struct ClosePackage closePackage = syscallPackage.closePackage;

            struct ContikiSocket xSocket = socketArray[closePackage.sockfd];

            if (xSocket.initialized == 0) {
                printf("Socket not found...\n");
                goto returnResult;
            }

            response = pico_socket_close(xSocket.tcp_conn);

            if (response != 0) {
                printf("Error closing socket with response: %d\n", response);
            }

        } else if (strcmp(syscallPackage.syscallId, "freertos_init") == 0){

            response = resetPacketDrillTask();

        } else {
                syscallResponse.result = 0;
        }

        returnResult:

        memset(&ecData, 0, sizeof(struct EventCallbackData));
        syscallResponse.result = response;

        printf("Syscall response buffer received: %d...\n", syscallResponse.result);

        int numWrote = send(cfd, &syscallResponse, sizeof(struct SyscallResponsePackage), MSG_NOSIGNAL); // Suppressed -Werror=maybe-uninitialized on cfd

        if (numWrote == -1) {
            printf("Error writing socket response with errno %d...\n", errno);
        } else {
            printf("Successfully wrote socket response to Packetdrill...\n");
        }

    }

    if (numRead == 0) {
        printf("About to unlink\n");
    } else if (numRead == -1) {
        printf("Error reading from socket with errno %d...\n", errno);
    }

    if (close(cfd) == -1) {
        printf("Error closing socket...\n");
    }

    #ifdef __AFL_HAVE_MANUAL_CONTROL
    }
    #endif

    }

}

int resetPacketDrillTask() {
    int sizeSocketArray = socketCounter - 3;
    if (sizeSocketArray > 0) {
        
        //We want to close all the socket we opened during this session 
        for (int counter = 3; counter < socketCounter; counter++) {
            struct ContikiSocket xSocket = socketArray[counter];
            if (xSocket.initialized == SOCKET_TCP && xSocket.tcp_conn != NULL) {
                pico_socket_del(xSocket.tcp_conn);
                
            } 
        }

        memset(socketArray, 0, MAX_SOCKET_ARRAY * sizeof(struct ContikiSocket));

    }

    socketCounter = 3;

    printf("PacketDrill Handler Task Reset..\n");

    return sizeSocketArray;

}
