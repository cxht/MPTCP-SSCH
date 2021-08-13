/*
 * iperf, Copyright (c) 2014-2019, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any mac approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <linux/tcp.h>
//#include "iperf.h"
#include "iperf_api.h"
#include "iperf_tcp.h"
#include "net.h"
#include "cjson.h"

#include "sr.h"
#define SOCK_NAME "/tmp/conn_uds_fd"

#if defined(HAVE_FLOWLABEL)
#include "flowlabel.h"
#endif /* HAVE_FLOWLABEL */
/*
 * iperf, Copyright (c) 2014-2020, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */


#include "iperf_config.h"

#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/select.h>
#include <sys/socket.h>
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
//#include <netinet/tcp.h>

#include <net/if.h> // for IFNAMSIZ

#if defined(HAVE_CPUSET_SETAFFINITY)
#include <sys/param.h>
#include <sys/cpuset.h>
#endif /* HAVE_CPUSET_SETAFFINITY */

#if defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
# ifndef PRIu64
#  if sizeof(long) == 8
#   define PRIu64		"lu"
#  else
#   define PRIu64		"llu"
#  endif
# endif
#endif

#include "timer.h"
#include "queue.h"
#include "cjson.h"
#include "iperf_time.h"

#if defined(HAVE_SSL)
#include <openssl/bio.h>
#include <openssl/evp.h>
#endif // HAVE_SSL

#if !defined(__IPERF_API_H)
typedef uint64_t iperf_size_t;
#endif // __IPERF_API_H
#include <linux/tcp.h>
// ////////////////////////////////////
// ssize_t
// read_fd(int fd,  int *recvfd)
// {
//     struct msghdr   msg;
//     struct iovec    iov[1];
//     ssize_t         n;
//     int             newfd;
//     char buf[1];


// #ifdef  HAVE_MSGHDR_MSG_CONTROL
//     union {
//       struct cmsghdr    cm;
//       char              control[CMSG_SPACE(sizeof(int))];
//     } control_un;
//     struct cmsghdr  *cmptr;

//     msg.msg_control = control_un.control;
//     msg.msg_controllen = sizeof(control_un.control);
// #else
//     msg.msg_accrights = (caddr_t) &newfd;
//     msg.msg_accrightslen = sizeof(int);
    
// #endif

//     msg.msg_name = NULL;
//     msg.msg_namelen = 0;

//     iov[0].iov_base = buf;
//     iov[0].iov_len = sizeof(int);
//     msg.msg_iov = iov;
//     msg.msg_iovlen = 1;

//     if ( (n = recvmsg(fd, &msg, 0)) <= 0)
//     {
        
//         return(n);
//     }
//     printf("err:%d %s",errno,strerror(errno));
//     //printf("[child]in_read_fd_recvlen:%d\naclen:%d\nn:%d",msg.msg_accrights,msg.msg_accrightslen,n);
// #ifdef  HAVE_MSGHDR_MSG_CONTROL
//     if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
//         cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
//         if (cmptr->cmsg_level != SOL_SOCKET)
//         {
//             //err_quit("control level != SOL_SOCKET");
//             printf("sol_socket error!\n");
//             exit(-1);
//         }
//         if (cmptr->cmsg_type != SCM_RIGHTS)
//         {
//             //err_quit("control type != SCM_RIGHTS");
//             printf("sol_socket error!\n");
//             exit(-1);
//         }
//         *recvfd = *((int *) CMSG_DATA(cmptr));
//         printf("\nread recvfd %d\n",*recvfd);
//     } else
//         *recvfd = -1;       /* descriptor was not passed */
// #else
// /* *INDENT-OFF* */
    
//     if (msg.msg_accrightslen == sizeof(int))
//      {   
//          *recvfd = newfd;
//          //printf("in_read_fd_recvfd:%d",*recvfd);
//     }
        
//     else
//         *recvfd = 5;       /* descriptor was not passed */
// /* *INDENT-ON* */
// #endif

//     return(n);
// }
// /* end read_fd */
// ssize_t
// write_fd(int fd,  int sendfd)
// {
//     struct msghdr   msg;
//     struct iovec    iov[1];
//     char buf[1];



// #ifdef  HAVE_MSGHDR_MSG_CONTROL
//     union {
//       struct cmsghdr    cm;
//       char              control[CMSG_SPACE(sizeof(int))];
//     } control_un;
//     struct cmsghdr  *cmptr;

//     msg.msg_control = control_un.control;
//     msg.msg_controllen = sizeof(control_un.control);

//     cmptr = CMSG_FIRSTHDR(&msg);
//     cmptr->cmsg_len = CMSG_LEN(sizeof(int));
//     cmptr->cmsg_level = SOL_SOCKET;
//     cmptr->cmsg_type = SCM_RIGHTS;
//     *((int *) CMSG_DATA(cmptr)) = sendfd;
//     printf("in_write_fd_have_msghdr_msg_control:%d\n",sendfd);
// #else
//     msg.msg_accrights = (caddr_t) &sendfd;
//     msg.msg_accrightslen = sizeof(int);
//     printf("in_write_fd_2:%d  len:%d\n",sendfd,msg.msg_accrightslen);
// #endif

//     msg.msg_name = NULL;
//     msg.msg_namelen = 0;

//     iov[0].iov_base = buf;
//     iov[0].iov_len = sizeof(int);
//     msg.msg_iov = iov;
//     msg.msg_iovlen = 1;

//     return(sendmsg(fd, &msg, 0));
// }
// /* end write_fd */
////////////////////////////////////

struct iperf_interval_results
{
    iperf_size_t bytes_transferred; /* bytes transfered in this interval */
    struct iperf_time interval_start_time;
    struct iperf_time interval_end_time;
    float     interval_duration;

    /* for UDP */
    int       interval_packet_count;
    int       interval_outoforder_packets;
    int       interval_cnt_error;
    int       packet_count;
    double    jitter;
    int       outoforder_packets;
    int       cnt_error;

    int omitted;
#if (defined(linux) || defined(__FreeBSD__) || defined(__NetBSD__)) && \
	defined(TCP_INFO)
    struct tcp_info tcpInfo; /* getsockopt(TCP_INFO) for Linux, {Free,Net}BSD */
#else
    /* Just placeholders, never accessed. */
    char *tcpInfo;
#endif
    int interval_retrans;
    int interval_sacks;
    int snd_cwnd;
    TAILQ_ENTRY(iperf_interval_results) irlistentries;
    void     *custom_data;
    int rtt;
    int rttvar;
    int pmtu;
};

struct iperf_stream_result
{
    iperf_size_t bytes_received;
    iperf_size_t bytes_sent;
    iperf_size_t bytes_received_this_interval;
    iperf_size_t bytes_sent_this_interval;
    iperf_size_t bytes_sent_omit;
    int stream_prev_total_retrans;
    int stream_retrans;
    int stream_prev_total_sacks;
    int stream_sacks;
    int stream_max_rtt;
    int stream_min_rtt;
    int stream_sum_rtt;
    int stream_count_rtt;
    int stream_max_snd_cwnd;
    struct iperf_time start_time;
    struct iperf_time end_time;
    struct iperf_time start_time_fixed;
    double sender_time;
    double receiver_time;
    TAILQ_HEAD(irlisthead, iperf_interval_results) interval_results;
    void     *data;
};

#define COOKIE_SIZE 37		/* size of an ascii uuid */
struct iperf_settings
{
    int       domain;               /* AF_INET or AF_INET6 */
    int       socket_bufsize;       /* window size for TCP */
    int       blksize;              /* size of read/writes (-l) */
    iperf_size_t  rate;                 /* target data rate for application pacing*/
    iperf_size_t  bitrate_limit;   /* server's maximum allowed total data rate for all streams*/
    double        bitrate_limit_interval;  /* interval for avaraging total data rate */
    int           bitrate_limit_stats_per_interval;     /* calculated number of stats periods for averaging total data rate */
    uint64_t  fqrate;               /* target data rate for FQ pacing*/
    int	      pacing_timer;	    /* pacing timer in microseconds */
    int       burst;                /* packets per burst */
    int       mss;                  /* for TCP MSS */
    int       ttl;                  /* IP TTL option */
    int       tos;                  /* type of service bit */
    int       flowlabel;            /* IPv6 flow label */
    iperf_size_t bytes;             /* number of bytes to send */
    iperf_size_t blocks;            /* number of blocks (packets) to send */
    char      unit_format;          /* -f */
    int       num_ostreams;         /* SCTP initmsg settings */
    int       dont_fragment;        /* Whether to set IP flag Do-Not_Fragment */
#if defined(HAVE_SSL)
    char      *authtoken;           /* Authentication token */
    char      *client_username;
    char      *client_password;
    EVP_PKEY  *client_rsa_pubkey;
#endif // HAVE_SSL
    int	      connect_timeout;	    /* socket connection timeout, in ms */
    int       idle_timeout;         /* server idle time timeout */
    struct iperf_time rcv_timeout;  /* Timeout for receiving messages in active mode, in us */
};

struct iperf_test;

double set_start = 0.0;
float state[32];
char state_string[128];
int len_string = 0;
char subflow_num[16];
int subflow_num_int = 0;


struct iperf_stream
{
    struct iperf_test* test;

    /* configurable members */
    int       local_port;
    int       remote_port;
    int       socket;
    int       id;
    int       sender;
	/* XXX: is settings just a pointer to the same struct in iperf_test? if not, 
		should it be? */
    struct iperf_settings *settings;	/* pointer to structure settings */

    /* non configurable members */
    struct iperf_stream_result *result;	/* structure pointer to result */
    Timer     *send_timer;
    int       green_light;
    int       buffer_fd;	/* data to send, file descriptor */
    char      *buffer;		/* data to send, mmapped */
    int       pending_size;     /* pending data to send */
    int       diskfile_fd;	/* file to send, file descriptor */
    int	      diskfile_left;	/* remaining file data on disk */

    /*
     * for udp measurements - This can be a structure outside stream, and
     * stream can have a pointer to this
     */
    int       packet_count;
    int	      peer_packet_count;
    int       omitted_packet_count;
    double    jitter;
    double    prev_transit;
    int       outoforder_packets;
    int       omitted_outoforder_packets;
    int       cnt_error;
    int       omitted_cnt_error;
    uint64_t  target;

    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;

    int       (*rcv) (struct iperf_stream * stream);
    int       (*snd) (struct iperf_stream * stream);

    /* chained send/receive routines for -F mode */
    int       (*rcv2) (struct iperf_stream * stream);
    int       (*snd2) (struct iperf_stream * stream);

//    struct iperf_stream *next;
    SLIST_ENTRY(iperf_stream) streams;

    void     *data;
};

struct protocol {
    int       id;
    char      *name;
    int       (*accept)(struct iperf_test *);
    int       (*listen)(struct iperf_test *);
    int       (*connect)(struct iperf_test *);
    int       (*send)(struct iperf_stream *);
    int       (*recv)(struct iperf_stream *);
    int       (*init)(struct iperf_test *);
    SLIST_ENTRY(protocol) protocols;
};

struct iperf_textline {
    char *line;
    TAILQ_ENTRY(iperf_textline) textlineentries;
};

struct xbind_entry {
    char *name;
    struct addrinfo *ai;
    TAILQ_ENTRY(xbind_entry) link;
};

enum iperf_mode {
	SENDER = 1,
	RECEIVER = 0,
	BIDIRECTIONAL = -1
};

struct iperf_test
{
    char      role;                             /* 'c' lient or 's' erver */
    enum iperf_mode mode;
    int       sender_has_retransmits;
    int       other_side_has_retransmits;       /* used if mode == BIDIRECTIONAL */
    struct protocol *protocol;
    signed char state;
    char     *server_hostname;                  /* -c option */
    char     *tmp_template;
    char     *bind_address;                     /* first -B option */
    char     *bind_dev;                         /* bind to network device */
    TAILQ_HEAD(xbind_addrhead, xbind_entry) xbind_addrs; /* all -X opts */
    int       bind_port;                        /* --cport option */
    int       server_port;
    int       omit;                             /* duration of omit period (-O flag) */
    int       duration;                         /* total duration of test (-t flag) */
    char     *diskfile_name;			/* -F option */
    int       affinity, server_affinity;	/* -A option */
#if defined(HAVE_CPUSET_SETAFFINITY)
    cpuset_t cpumask;
#endif /* HAVE_CPUSET_SETAFFINITY */
    char     *title;				/* -T option */
    char     *extra_data;			/* --extra-data */
    char     *congestion;			/* -C option */
    char     *congestion_used;			/* what was actually used */
    char     *remote_congestion_used;		/* what the other side used */
    char     *pidfile;				/* -P option */

    char     *logfile;				/* --logfile option */
    FILE     *outfile;

    int       ctrl_sck;
    int       listener;
    int       prot_listener;

    int	      ctrl_sck_mss;			/* MSS for the control channel */

#if defined(HAVE_SSL)
    char      *server_authorized_users;
    EVP_PKEY  *server_rsa_private_key;
    int       server_skew_threshold;
#endif // HAVE_SSL

    /* boolean variables for Options */
    int       daemon;                           /* -D option */
    int       one_off;                          /* -1 option */
    int       no_delay;                         /* -N option */
    int       reverse;                          /* -R option */
    int       bidirectional;                    /* --bidirectional */
    int	      verbose;                          /* -V option - verbose mode */
    int	      json_output;                      /* -J option - JSON output */
    int	      zerocopy;                         /* -Z option - use sendfile */
    int       debug;				/* -d option - enable debug */
    int	      get_server_output;		/* --get-server-output */
    int	      udp_counters_64bit;		/* --use-64-bit-udp-counters */
    int       forceflush; /* --forceflush - flushing output at every interval */
    int	      multisend;
    int	      repeating_payload;                /* --repeating-payload */
    int       timestamps;			/* --timestamps */
    char     *timestamp_format;

    char     *json_output_string; /* rendered JSON output if json_output is set */
    /* Select related parameters */
    int       max_fd;
    fd_set    read_set;                         /* set of read sockets */
    fd_set    write_set;                        /* set of write sockets */

    /* Interval related members */ 
    int       omitting;
    double    stats_interval;
    double    reporter_interval;
    void      (*stats_callback) (struct iperf_test *);
    void      (*reporter_callback) (struct iperf_test *);
    Timer     *omit_timer;
    Timer     *timer;
    int        done;
    Timer     *stats_timer;
    Timer     *reporter_timer;

    double cpu_util[3];                            /* cpu utilization of the test - total, user, system */
    double remote_cpu_util[3];                     /* cpu utilization for the remote host/client - total, user, system */

    int       num_streams;                      /* total streams in the test (-P) */

    iperf_size_t bytes_sent;
    iperf_size_t blocks_sent;

    iperf_size_t bytes_received;
    iperf_size_t blocks_received;

    iperf_size_t bitrate_limit_stats_count;               /* Number of stats periods accumulated for server's total bitrate average */
    iperf_size_t *bitrate_limit_intervals_traffic_bytes;  /* Pointer to a cyclic array that includes the last interval's bytes transferred */
    iperf_size_t bitrate_limit_last_interval_index;       /* Index of the last interval traffic insrted into the cyclic array */
    int          bitrate_limit_exceeded;                  /* Set by callback routine when average data rate exceeded the server's bitrate limit */

    int server_last_run_rc;                      /* Save last server run rc for next test */
    uint server_forced_idle_restarts_count;      /* count number of forced server restarts to make sure it is not stack */
    uint server_forced_no_msg_restarts_count;    /* count number of forced server restarts to make sure it is not stack */
    uint server_test_number;                     /* count number of tests performed by a server */

    char      cookie[COOKIE_SIZE];
//    struct iperf_stream *streams;               /* pointer to list of struct stream */
    SLIST_HEAD(slisthead, iperf_stream) streams;
    struct iperf_settings *settings;

    SLIST_HEAD(plisthead, protocol) protocols;

    /* callback functions */
    void      (*on_new_stream)(struct iperf_stream *);
    void      (*on_test_start)(struct iperf_test *);
    void      (*on_connect)(struct iperf_test *);
    void      (*on_test_finish)(struct iperf_test *);

    /* cJSON handles for use when in -J mode */\
    cJSON *json_top;
    cJSON *json_start;
    cJSON *json_connected;
    cJSON *json_intervals;
    cJSON *json_end;

    /* Server output (use on client side only) */
    char *server_output_text;
    cJSON *json_server_output;

    /* Server output (use on server side only) */
    TAILQ_HEAD(iperf_textlisthead, iperf_textline) server_output_list;

};

/* default settings */
#define PORT 5201  /* default port to listen on (don't use the same port as iperf2) */
#define uS_TO_NS 1000
#define mS_TO_US 1000
#define SEC_TO_mS 1000
#define SEC_TO_US 1000000LL
#define UDP_RATE (1024 * 1024) /* 1 Mbps */
#define OMIT 0 /* seconds */
#define DURATION 10 /* seconds */

#define SEC_TO_NS 1000000000LL	/* too big for enum/const on some platforms */
#define MAX_RESULT_STRING 4096

#define UDP_BUFFER_EXTRA 1024

/* constants for command line arg sanity checks */
#define MB (1024 * 1024)
#define MAX_TCP_BUFFER (512 * MB)
#define MAX_BLOCKSIZE MB
/* Minimum size UDP send is the size of two 32-bit ints followed by a 64-bit int */
#define MIN_UDP_BLOCKSIZE (4 + 4 + 8)
/* Maximum size UDP send is (64K - 1) - IP and UDP header sizes */
#define MAX_UDP_BLOCKSIZE (65535 - 8 - 20)
#define MIN_INTERVAL 0.1
#define MAX_INTERVAL 60.0
#define MAX_TIME 86400
#define MAX_BURST 1000
#define MAX_MSS (9 * 1024)
#define MAX_STREAMS 128

#define TIMESTAMP_FORMAT "%c "

extern int gerror; /* error value from getaddrinfo(3), for use in internal error handling */


/* iperf_tcp_recv
 *
 * receives the data for TCP
 */




int
iperf_tcp_recv(struct iperf_stream *sp)
{
    int r;

    r = Nread(sp->socket, sp->buffer, sp->settings->blksize, Ptcp);

    if (r < 0)
        return r;

    /* Only count bytes received while we're in the correct state. */
    if (sp->test->state == TEST_RUNNING) {
	sp->result->bytes_received += r;
	sp->result->bytes_received_this_interval += r;
    }
    else {
	if (sp->test->debug)
	    printf("Late receive, state = %d\n", sp->test->state);
    }

    return r;
}


/* iperf_tcp_send 
 *
 * sends the data for TCP
 */
int
iperf_tcp_send(struct iperf_stream *sp)
{
    int r;

    if (!sp->pending_size)
	sp->pending_size = sp->settings->blksize;

    if (sp->test->zerocopy)
	r = Nsendfile(sp->buffer_fd, sp->socket, sp->buffer, sp->pending_size);
    else
	r = Nwrite(sp->socket, sp->buffer, sp->pending_size, Ptcp);

    if (r < 0)
        return r;

    sp->pending_size -= r;
    sp->result->bytes_sent += r;
    sp->result->bytes_sent_this_interval += r;

    if (sp->test->debug)
	printf("sent %d bytes of %d, pending %d, total %" PRIu64 "\n",
	    r, sp->settings->blksize, sp->pending_size, sp->result->bytes_sent);

    return r;
}


/* iperf_tcp_accept
 *
 * accept a new TCP stream connection
 */
int
iperf_tcp_accept(struct iperf_test * test)
{
    int     s;
    signed char rbuf = ACCESS_DENIED;
    char    cookie[COOKIE_SIZE];
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);
    if ((s = accept(test->listener, (struct sockaddr *) &addr, &len)) < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (Nread(s, cookie, COOKIE_SIZE, Ptcp) < 0) {
        i_errno = IERECVCOOKIE;
        return -1;
    }

    if (strcmp(test->cookie, cookie) != 0) {
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Ptcp) < 0) {
            i_errno = IESENDMESSAGE;
            return -1;
        }
        close(s);
    }

    return s;
}


/* iperf_tcp_listen
 *
 * start up a listener for TCP stream connections
 */
int
iperf_tcp_listen(struct iperf_test *test)
{
    int s, opt;
    socklen_t optlen;
    int saved_errno;
    int rcvbuf_actual, sndbuf_actual;

    s = test->listener;

    /*
     * If certain parameters are specified (such as socket buffer
     * size), then throw away the listening socket (the one for which
     * we just accepted the control connection) and recreate it with
     * those parameters.  That way, when new data connections are
     * set, they'll have all the correct parameters in place.
     *
     * It's not clear whether this is a requirement or a convenience.
     */
    if (test->no_delay || test->settings->mss || test->settings->socket_bufsize) {
	struct addrinfo hints, *res;
	char portstr[6];

        FD_CLR(s, &test->read_set);
        close(s);

        snprintf(portstr, 6, "%d", test->server_port);
        memset(&hints, 0, sizeof(hints));

	/*
	 * If binding to the wildcard address with no explicit address
	 * family specified, then force us to get an AF_INET6 socket.
	 * More details in the comments in netanounce().
	 */
	if (test->settings->domain == AF_UNSPEC && !test->bind_address) {
	    hints.ai_family = AF_INET6;
	}
	else {
	    hints.ai_family = test->settings->domain;
	}
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        if ((gerror = getaddrinfo(test->bind_address, portstr, &hints, &res)) != 0) {
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if ((s = socket(res->ai_family, SOCK_STREAM, 0)) < 0) {
	    freeaddrinfo(res);
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if (test->no_delay) {
            opt = 1;
            if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETNODELAY;
                return -1;
            }
        }
        // XXX: Setting MSS is very buggy!
        if ((opt = test->settings->mss)) {
            if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETMSS;
                return -1;
            }
        }
        if ((opt = test->settings->socket_bufsize)) {
            if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
            if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
        }
#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If fq socket pacing is specified, enable it. */
    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */
    {
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Setting application pacing to %u\n", rate);
	    }
	}
    }
        opt = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IEREUSEADDR;
            return -1;
        }

	/*
	 * If we got an IPv6 socket, figure out if it shoudl accept IPv4
	 * connections as well.  See documentation in netannounce() for
	 * more details.
	 */
#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC || test->settings->domain == AF_INET)) {
	    if (test->settings->domain == AF_UNSPEC)
		opt = 0;
	    else 
		opt = 1;
	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
			   (char *) &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
		i_errno = IEV6ONLY;
		return -1;
	    }
	}
#endif /* IPV6_V6ONLY */

        if (bind(s, (struct sockaddr *) res->ai_addr, res->ai_addrlen) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        freeaddrinfo(res);

        if (listen(s, INT_MAX) < 0) {
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        test->listener = s;
    }
    
    /* Read back and verify the sender socket buffer size */
    optlen = sizeof(sndbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("SNDBUF is %u, expecting %u\n", sndbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > sndbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    /* Read back and verify the receiver socket buffer size */
    optlen = sizeof(rcvbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("RCVBUF is %u, expecting %u\n", rcvbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > rcvbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    if (test->json_output) {
	cJSON_AddNumberToObject(test->json_start, "sock_bufsize", test->settings->socket_bufsize);
	cJSON_AddNumberToObject(test->json_start, "sndbuf_actual", sndbuf_actual);
	cJSON_AddNumberToObject(test->json_start, "rcvbuf_actual", rcvbuf_actual);
    }

    return s;
}



#define MPTCP_INFO_FLAG_SAVE_MASTER 0x01
#define IP_ADDRESS 16
#define HAVE_MSGHDR_MSG_CONTROL

void test_print(float *state,int num)
{
    int i =0 ;
    for(;i<num;i++)
    {
        printf("state %d : %f\n",i,state[i]);
        
    }
}

void float2string(float *f_array,char *string,int len_f,int *len_s)
{
    int i =0;
    float f = 0.0;
    char temp[16];
    string[0]='[';
    string[1] = '\0';
    for(;i<len_f;i++)
    {
        f = f_array[i];
        sprintf(temp,"%.2f",f);
        strcat(string,temp);
        strcat(string,",");
        //printf("%s\n",string);
    }
    
    strcat(string,"]\0");
    *len_s = strlen(string);
    
}


int connect_NAF_as_server(void *main_fd)
{
    char *sendbuf_test="hallo!!!!!!!hahahahahahhaha";
    int server_sockfd = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    int ret = 0;
    int fd = *(int *)main_fd;
    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(12345);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    

    
    ///bind
    if(bind(server_sockfd,(struct sockaddr *)&server_sockaddr,sizeof(server_sockaddr))==-1)
    {
        perror("[SERVER]bind err\n");
        exit(1);
    }
    printf("[SERVER]after bind\n");

    ///listen
    if(listen(server_sockfd,20) == -1)
    {
        perror("[SERVER]listen err\n");
        exit(1);
    }
    printf("[SERVER]after listen\n");
    
    char buffer[64];
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);

    
    int conn = accept(server_sockfd, (struct sockaddr*)&client_addr, &length);
    if(conn<0)
    {
        perror("[SERVER]connect err");
        exit(1);
    }
    printf("[SERVER]after accpet");
    char ratio[64];
    socklen_t len_ratio = 64;

    //step 2: listening and set split ratio*/
    for(;;)
    {
        
        memset(buffer,0,sizeof(buffer));
        recv(conn, buffer, sizeof(buffer),0);
        memcpy(ratio,buffer,len_ratio);
        //printf("[SERVER-%d]Getting bytes from NAF: %s",server_sockfd,buffer);
        fflush(stdout);
        printf("\n[SERVER-%d]ratio: %s\n",server_sockfd,ratio);
        fflush(stdout);
        ret = setsockopt(fd,6,MPTCP_SPLIT_RATIO,ratio,len_ratio);
        if(ret<0)
        {
            printf("[SERVER]set split ratio error : %d,%s",errno,strerror(errno));
        }

        
    }
    close(conn);


}

int transmit_to_NAF(void *naf_fd)
{
    int ret = 0;
    int fd = *(int *)naf_fd;
    while(1){
        ret = send(fd,state_string,len_string,0);
        
        if(ret<0)
        {
            printf("[transmit]return state to naf err\n");
        } 
        usleep(150000);
    }
}


int monitor_state(void *main_fd)
{
    /////////////////////child pid : for send minfo ////////
    char *sendbuf_test="hallo!!!!!!!hahahahahahhaha";
    int ret = 0;
    int fd = *(int *)main_fd;
    ///////////////////
    //step1.init minfo
    struct mptcp_info minfo;
    struct mptcp_meta_info meta_info;
    struct tcp_info initial;
    struct tcp_info others[3];
    struct mptcp_sub_info others_info[3];
    int val = MPTCP_INFO_FLAG_SAVE_MASTER;
    //char address[IP_ADDRESS];

    minfo.tcp_info_len = sizeof(struct tcp_info);
    minfo.sub_len = sizeof(others);
    
    minfo.meta_len = sizeof(struct mptcp_meta_info);
    minfo.meta_info = &meta_info;
    minfo.initial = &initial;
    minfo.subflows = &others;
    minfo.sub_info_len = sizeof(struct mptcp_sub_info);
    minfo.total_sub_info_len = sizeof(others_info);
    minfo.subflow_info = &others_info;   

    socklen_t len_minfo = sizeof(minfo);


    int retrans_pre[8] =  {0};
    int retrans_post[8] = {0};
    int retrans[8] = {0};

    
    //step2. build a socket with NAF
    ret = 0;
    char *naf_address="127.0.0.1";
    int naf_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(naf_fd == -1)
        printf("[CLIENT]build socket error");
    struct sockaddr_in naf_serv_addr;
    memset(&naf_serv_addr, 0, sizeof(naf_serv_addr)); 
    naf_serv_addr.sin_family = AF_INET;            
    naf_serv_addr.sin_addr.s_addr = inet_addr(naf_address); 
    naf_serv_addr.sin_port = htons(12346);
    
    do
    {
        ret = connect(naf_fd, (struct sockaddr*)&naf_serv_addr, sizeof(naf_serv_addr));
        if(ret>=0)
        {
            printf("[CLIENT-%d]Connect NAF success\n",naf_fd);
            break;
        }
        printf("[CLIENT-%d]Connect NAF error...reconnecting....\n",naf_fd);
        sleep(1);
        
    }while(ret <0);

    do
    {
        
        ret = getsockopt(fd,6,MPTCP_INFO,&minfo,&len_minfo);
        if(ret>=0)
        {
                printf("[CLIENT]get SUBFLOW NUM for action size successfully!\n");
                break;
        }
        printf("[CLIENT]return subflownum to naf err,err num:%d,%s\n",errno,strerror(errno));
        
    } while(ret<0);

    

    
    subflow_num_int = minfo.sub_len/minfo.tcp_info_len;
    
    sprintf( subflow_num, "%d", subflow_num_int ); // C4996
    printf("subflow num : %s\n",subflow_num);
    

 
    //get subflow number for init action size/*
    
    ret = send(naf_fd,subflow_num,sizeof(subflow_num),0);
    
    if(ret<0)
    {
        printf("[CLIENT]return subflownum to naf err,err num:%d,%s\n",errno,strerror(errno));
    } 



    float default_rtt = 1.0;
    //ret = send(naf_fd,sendbuf_test,sizeof(sendbuf_test),0);
    
    unsigned int  pre_send[subflow_num_int];
    unsigned int  post_send[subflow_num_int];
    float th[subflow_num_int];

    int  iter = 0;
    memset(pre_send,0,subflow_num_int);
    memset(post_send,0,subflow_num_int);
    memset(th,0.0,subflow_num_int);

    //clock_t start,end;
    //start = clock();
    struct iperf_time iperf_start,iperf_end,iperf_diff;
    iperf_time_now(&iperf_start);
    for(;;iter++){    
        // keep listening and returning mptcp info
        int num =0;
        
        ret = getsockopt(fd,6,MPTCP_INFO,&minfo,&len_minfo);
        //end = clock();
        if(iter%5==0)
        {
            iperf_time_now(&iperf_end);
            iperf_time_diff(&iperf_end,&iperf_start,&iperf_diff);
            iperf_start.secs = iperf_end.secs;
            iperf_start.usecs = iperf_end.usecs;
        }
        if(ret == -1)
        {
            printf("[CLIENT]getsockfd error! code = %d,%s",errno,strerror(errno));
            fflush(stdout);
        }
        else{
            //printf("[CLIENT]get minfo sucess! code = %d,%s",errno,strerror(errno));
            fflush(stdout);
            state_string[0]='\0';
            int len_sub = minfo.sub_len/minfo.tcp_info_len;
            float rtt = 0.0 ;
            int unacked =  0;
            float sacked =  0.0;
            float lost =  0.0;
            int cwnd = 0;
            
            for(int i=0;i<len_sub ;i++)
            {
                rtt = (minfo.subflows+i)->tcpi_rtt ;
                unacked = (minfo.subflows+i)->tcpi_unacked;
                sacked = (minfo.subflows+i)->tcpi_sacked;
                lost = (minfo.subflows+i)->tcpi_lost;
                cwnd = (minfo.subflows+i)->tcpi_snd_cwnd;
                retrans_post[i] = (minfo.subflows+i)->tcpi_total_retrans;
                retrans[i] = retrans_post[i] - retrans_pre[i];
                
                retrans_pre[i] = retrans_post[i];
                
     
                state[num++] = rtt / 1000;  //ms
                
                
                
                
                if(iter>5)
                    state[num++] = th[i];
                else
                {
                    state[num++] = 10;
                    default_rtt = rtt / 1000;
                    //printf("default_rtt : %f\n",default_rtt);
                }
                if(iter%5==0)
                {
                    post_send[i] = (minfo.subflows+i)->tcpi_bytes_sent;         //calculate bw

                    float diff = iperf_diff.secs * 1000 + (float)iperf_diff.usecs /1000;      //ms
                    th[i] = (float)((post_send[i]-pre_send[i])*8) / (diff ); //throughput kbps
                    pre_send[i] = post_send[i]; 
                    printf("\npath:%d  th:%lf\n",i,th[i]);
                }
               
                state[num++] = (float)retrans[i];
                state[num++] = (float)unacked;
                state[num++] = (float)cwnd;
                
            }
            
            fflush(stdout);
            
            float2string(state,&state_string,num,&len_string);

            //printf("[CLIENT]State string:%s will send to NAF,len : %d",state_string,len_string);
            //test_print(state,num);
            
        }
        if(iter==0)
        {
            pthread_t transmit; 
            if (pthread_create(&transmit,NULL, transmit_to_NAF,&naf_fd) != 0)
            {
                printf("[monitor]create TRANSMIT error\n");
                fflush(stdout);
            }
        }

        usleep(30000);
    }
}


/* iperf_tcp_connect
 *
 * connect to a TCP stream listener
 * This function is roughly similar to netdial(), and may indeed have
 * been derived from it at some point, but it sets many TCP-specific
 * options between socket creation and connection.
 */
int
iperf_tcp_connect(struct iperf_test *test)
{
    struct addrinfo hints, *local_res, *server_res;
    char portstr[6];
    int s, opt;
    socklen_t optlen;
    int saved_errno;
    int rcvbuf_actual, sndbuf_actual;

    if (test->bind_address) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = test->settings->domain;
        hints.ai_socktype = SOCK_STREAM;
        if ((gerror = getaddrinfo(test->bind_address, NULL, &hints, &local_res)) != 0) {
            i_errno = IESTREAMCONNECT;
            return -1;
        }
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = test->settings->domain;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", test->server_port);
    if ((gerror = getaddrinfo(test->server_hostname, portstr, &hints, &server_res)) != 0) {
	if (test->bind_address)
	    freeaddrinfo(local_res);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if ((s = socket(server_res->ai_family, SOCK_STREAM, 0)) < 0) {
	if (test->bind_address)
	    freeaddrinfo(local_res);
	freeaddrinfo(server_res);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    /*
     * Various ways to bind the local end of the connection.
     * 1.  --bind (with or without --cport).
     */
    if (test->bind_address) {
        struct sockaddr_in *lcladdr;
        lcladdr = (struct sockaddr_in *)local_res->ai_addr;
        lcladdr->sin_port = htons(test->bind_port);

        if (bind(s, (struct sockaddr *) local_res->ai_addr, local_res->ai_addrlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(local_res);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESTREAMCONNECT;
            return -1;
        }
        freeaddrinfo(local_res);
    }
    /* --cport, no --bind */
    else if (test->bind_port) {
	size_t addrlen;
	struct sockaddr_storage lcl;

	/* IPv4 */
	if (server_res->ai_family == AF_INET) {
	    struct sockaddr_in *lcladdr = (struct sockaddr_in *) &lcl;
	    lcladdr->sin_family = AF_INET;
	    lcladdr->sin_port = htons(test->bind_port);
	    lcladdr->sin_addr.s_addr = INADDR_ANY;
	    addrlen = sizeof(struct sockaddr_in);
	}
	/* IPv6 */
	else if (server_res->ai_family == AF_INET6) {
	    struct sockaddr_in6 *lcladdr = (struct sockaddr_in6 *) &lcl;
	    lcladdr->sin6_family = AF_INET6;
	    lcladdr->sin6_port = htons(test->bind_port);
	    lcladdr->sin6_addr = in6addr_any;
	    addrlen = sizeof(struct sockaddr_in6);
	}
	/* Unknown protocol */
	else {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IEPROTOCOL;
            return -1;
	}

        if (bind(s, (struct sockaddr *) &lcl, addrlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESTREAMCONNECT;
            return -1;
        }
    }

    /* Set socket options */
    if (test->no_delay) {
        opt = 1;
        if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETNODELAY;
            return -1;
        }
    }
    if ((opt = test->settings->mss)) {
        if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETMSS;
            return -1;
        }
    }
    if ((opt = test->settings->socket_bufsize)) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }

    /* Read back and verify the sender socket buffer size */
    optlen = sizeof(sndbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("SNDBUF is %u, expecting %u\n", sndbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > sndbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    /* Read back and verify the receiver socket buffer size */
    optlen = sizeof(rcvbuf_actual);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf_actual, &optlen) < 0) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
	i_errno = IESETBUF;
	return -1;
    }
    if (test->debug) {
	printf("RCVBUF is %u, expecting %u\n", rcvbuf_actual, test->settings->socket_bufsize);
    }
    if (test->settings->socket_bufsize && test->settings->socket_bufsize > rcvbuf_actual) {
	i_errno = IESETBUF2;
	return -1;
    }

    if (test->json_output) {
	cJSON_AddNumberToObject(test->json_start, "sock_bufsize", test->settings->socket_bufsize);
	cJSON_AddNumberToObject(test->json_start, "sndbuf_actual", sndbuf_actual);
	cJSON_AddNumberToObject(test->json_start, "rcvbuf_actual", rcvbuf_actual);
    }

#if defined(HAVE_FLOWLABEL)
    if (test->settings->flowlabel) {
        if (server_res->ai_addr->sa_family != AF_INET6) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETFLOW;
            return -1;
	} 
    else {
	    struct sockaddr_in6* sa6P = (struct sockaddr_in6*) server_res->ai_addr;
            char freq_buf[sizeof(struct in6_flowlabel_req)];
            struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
            int freq_len = sizeof(*freq);

            memset(freq, 0, sizeof(*freq));
            freq->flr_label = htonl(test->settings->flowlabel & IPV6_FLOWINFO_FLOWLABEL);
            freq->flr_action = IPV6_FL_A_GET;
            freq->flr_flags = IPV6_FL_F_CREATE;
            freq->flr_share = IPV6_FL_S_ANY;
            memcpy(&freq->flr_dst, &sa6P->sin6_addr, 16);

            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            }
            sa6P->sin6_flowinfo = freq->flr_label;

            opt = 1;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            } 
	}
    }
#endif /* HAVE_FLOWLABEL */

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If socket pacing is specified try to enable it. */
    if (test->settings->fqrate) {
	/* Convert bits per second to bytes per second */
	unsigned int fqrate = test->settings->fqrate / 8;
	if (fqrate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", fqrate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &fqrate, sizeof(fqrate)) < 0) {
		warning("Unable to set socket pacing");
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */
    {
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Setting application pacing to %u\n", rate);
	    }
	}
    }
        //int unix_snd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        int unix_snd_sock;
        unix_snd_sock = make_connect();
        int ret = send_fd(unix_snd_sock, s, "sendmsg"); 
        sleep(1);
        if(ret<0)
        {
            printf("[MAIN-%d]UNIX_SEND_ERR ,errno:%d,%s\n",s,errno,strerror(errno));
            fflush(stdout);
        }
        else
        {
            printf("[MAIN-%d]UNIX_SEND_success! %d,%s\n",s,errno,strerror(errno));
            fflush(stdout);
        }
        //char sch[]="random";
        //ret = 0;
        //socklen_t len_sch = sizeof(sch);
        // ret = setsockopt(s,6,MPTCP_SCHEDULER,sch,sizeof(sch));
        // if(ret<0)
        // {
        //     printf("[MAIN-%d]set socket opt error!errno:%d,%s\n",s,errno,strerror(errno));
        //     fflush(stdout);
        // }
        // else
        // {
        //     printf("[MAIN-%d]set socket success![%s] %d,%s\n",s,sch,errno,strerror(errno));
        //     fflush(stdout);
        // }
    if (connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen) < 0 && errno != EINPROGRESS) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    freeaddrinfo(server_res);

    /* Send cookie for verification */
    if (Nwrite(s, test->cookie, COOKIE_SIZE, Ptcp) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
        i_errno = IESENDCOOKIE;
        return -1;
    }

    // //from here:! interact with NAF and kernel!
    // pthread_t th_server,th_client; 
    // if (pthread_create(&th_server,NULL, connect_NAF_as_server, &s) != 0)
    // {
    //     printf("[main]create SERVER error\n");
    //     fflush(stdout);
    // }
            
    // if (pthread_create(&th_client,NULL, monitor_state, &s) != 0)
    // {
    //     printf("[main]create CLIENT error\n");
    //     fflush(stdout);
    // }                        
    sleep(1);
    return s;
}

