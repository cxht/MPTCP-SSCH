cdef extern from "sr.h":
	extern int connect_socket()
	extern int send_fd(int sock, int fd, char* data)
	extern int recv_fd(int sock, char* data)
	extern int get_subflownum(int fd)
	extern int get_mptcpinfo(int fd,float* state)
	void close_fd(int fd)
cdef extern from "stdlib.h":
	extern void *malloc(unsigned int num_bytes)
	extern void free(void *ptr)

def getsubflownum(fd):
	cdef int sfd = fd
	cdef int num = get_subflownum(sfd)
	return num
def getstate(fd):
	cdef int sfd = fd
	cdef float state[20]
	cdef int len = get_mptcpinfo(sfd,state)
	return state,len
def connect_unix():
	cdef int fd = connect_socket()
	print("get unix fd",str(fd))
	return fd

def fjs_recv_fd(sock):
	cdef int fd = sock
	cdef char* data = <char*>malloc(33)
	fd = recv_fd(fd, data)
	try:
		out_data = data
		return (fd, out_data)
	finally:
		free(data)
def fjs_send_fd(fd1, fd2, data):
	cdef int source = fd1
	cdef int des    = fd2
	send_fd(source, des, data)

def fjs_close_fd(fd):
	cdef int now_fd = fd
	close_fd(fd)
