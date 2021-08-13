#include <sys/socket.h> 
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#define SOCKET_NAME "/tmp/conn_uds_fd"

int send_fd(int sock, int fd, char* data);
int recv_fd(int sock, char *data);  
void close_fd(int fd);
int connect_socket();
int make_connect();
int get_mptcpinfo(int fd,float* state);
int get_subflownum(int fd);

int get_subflownum(int fd)
{
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

    //step2. build a socket with NAF
    int ret = 0;

    ret = getsockopt(fd,6,MPTCP_INFO,&minfo,&len_minfo);

    int subflow_num_int = minfo.sub_len/minfo.tcp_info_len;
    
    return subflow_num_int;
}
int get_mptcpinfo(int fd,float* state)
{
    struct mptcp_info minfo;
    struct mptcp_meta_info meta_info;
    struct tcp_info initial;
    struct tcp_info others[3];
    struct mptcp_sub_info others_info[3];
    int len_string = 0;
    char state_string[128];

    int val = MPTCP_INFO_FLAG_SAVE_MASTER;
 
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


    int total_retrans = 0;
    int total_bytes_sent = 0;
    
    //step2. build a socket with NAF
    int ret = 0;


        // keep listening and returning mptcp info
        int num =0;
        
        ret = getsockopt(fd,6,MPTCP_INFO,&minfo,&len_minfo);
        //end = clock();

        if(ret == -1)
        {
            printf("[CLIENT]getsockfd error! code = %d,%s",errno,strerror(errno));
            fflush(stdout);
        }
        else{
            //printf("[CLIENT]get minfo sucess! code = %d,%s",errno,strerror(errno));
            fflush(stdout);
            
            int len_sub = minfo.sub_len/minfo.tcp_info_len;
            float rtt = 0.0 ;
            int unacked =  0;
            float sacked =  0.0;
            float lost =  0.0;
            int cwnd = 0;
            
            for(int i=0;i<len_sub ;i++)
            {
                rtt = (minfo.subflows+i)->tcpi_rtt/1000 ;
                state[num++] = (float)rtt;
                total_bytes_sent = (minfo.subflows+i)->tcpi_bytes_sent;  
                state[num++] = (float)total_bytes_sent;  
                total_retrans = (minfo.subflows+i)->tcpi_total_retrans;
                state[num++] = (float)total_retrans; 
                unacked = (minfo.subflows+i)->tcpi_unacked;
                state[num++] = (float)unacked;
                cwnd = (minfo.subflows+i)->tcpi_snd_cwnd;
                state[num++] = (float)cwnd;
                sacked = (minfo.subflows+i)->tcpi_sacked;
                lost = (minfo.subflows+i)->tcpi_lost;
                state[num++] = (float)lost;
            }
            
            
            //float2string(state,&state_string,num,&len_string);
        }

    return num;
}
int connect_socket()
{
    int fd;
    int ret;
    struct sockaddr_un sun;
    fd = socket(AF_UNIX,SOCK_STREAM,0);
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path,SOCKET_NAME,sizeof(sun.sun_path) - 1);

    ret = connect(fd,(struct sockaddr *)&sun,sizeof(sun));
    if(ret<0)
    {
        printf("[connect_socket]connect error,%s",strerror(errno));
    }
    return fd;
}
int make_connect()
{
	int fd, size;
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("no1 socket build\n");
		return 0;
	}
	strncpy(sun.sun_path, SOCKET_NAME,sizeof(sun.sun_path) - 1);
	size = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (bind(fd, (struct sockaddr *)&sun, size) < 0) {
		printf("no2 bind\n,%s",strerror(errno));
		return 0;
	}

    //cxadd
    listen(fd,10);
    int connection_fd = accept(fd,NULL,NULL);
    if (connection_fd < 0) {
		printf("no3 accept\n");
		return 0;
	}
    return connection_fd;
    ///cx add end

	// strcpy(un.sun_path, name);
	// size = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	// if (connect(fd, (struct sockaddr *)&un, size) < 0) {
	// 	printf("no3\n");
	// 	return 0;
	// }
	// // if (listen(fd, 10) < 0) {
	// // 	printf("no3");
	// // }
 
	// // char* hello = "hello fjs";
	// // ssize_t out = send(fd, (void*)hello, strlen(hello), 0);
	// // send_fd(lis, lis);
	// return fd;
}
 
 
 
 
int send_fd(int sock, int fd, char* data)    
{    
    printf("here1: %s\n", data);
    struct iovec iov[1];    
    iov[0].iov_base = data;    
    iov[0].iov_len  = strlen(data);
    printf("len: %d\n", strlen(data));
    printf("here2: %s\n", iov[0].iov_base);  
  
    int cmsgsize = CMSG_LEN(sizeof(int));    
    struct cmsghdr* cmptr = (struct cmsghdr*)malloc(cmsgsize);    
    if(cmptr == NULL){    
        return -1;    
    }    
    cmptr->cmsg_level = SOL_SOCKET;    
    cmptr->cmsg_type = SCM_RIGHTS; // we are sending fd.    
    cmptr->cmsg_len = cmsgsize;    
    
    struct msghdr msg;    
    msg.msg_iov = iov;    
    msg.msg_iovlen = 1;    
    msg.msg_name = NULL;    
    msg.msg_namelen = 0;    
    msg.msg_control = cmptr;    
    msg.msg_controllen = cmsgsize;    
    *(int *)CMSG_DATA(cmptr) = fd;    
        
    int ret = sendmsg(sock, &msg, 0);    
    free(cmptr);    
    if (ret == -1){    
        return -1;    
    }    
    return 0;  
}    
    
int recv_fd(int sock, char* data)    
{   
    int cmsgsize = CMSG_LEN(sizeof(int));    
    struct cmsghdr* cmptr = (struct cmsghdr*)malloc(cmsgsize);    
    if (cmptr == NULL) {  
        return -1;  
    }  
    char buf[33]; // the max buf in msg. 
    memset(buf, 0, 33);  
    struct iovec iov[1];  
    iov[0].iov_base = buf;    
    iov[0].iov_len = sizeof(buf);    
    struct msghdr msg;
    msg.msg_iov = iov;    
    msg.msg_iovlen  = 1;    
    msg.msg_name = NULL;    
    msg.msg_namelen = 0;    
    msg.msg_control = cmptr;    
    msg.msg_controllen = cmsgsize;    
        
    int ret = recvmsg(sock, &msg, 0);  
       
    if (ret == -1) {    
        return -1;   
    }
    int fd = *(int *)CMSG_DATA(cmptr);
    strcpy(data, iov[0].iov_base);
    free(cmptr); 
    return fd;    
}
 
void close_fd(int fd)
{
    close(fd);
}
 
 
// int main()
// {
// 	int lis = serv_listen("/tmp/fjs.sock");
// 	printf("ok\n");
// 	char* hello = "hello fjs";
// 	// ssize_t out = send(lis, (void*)hello, strlen(hello), 0);
// 	send_fd(lis, lis);
 
//}