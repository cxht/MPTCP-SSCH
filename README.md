# MPTCP-SSCH
An MPTCP scheduler used RL

##  scheduler in kernel
the core file is "mptcp_random.c"
tcp.c : modified for tcp_sockopt 
other header files are modified 

##  RL framework
1. A gym enviroment for mptcp is in folder /classic_control.
To use C code in python, you should follow these operations.
c functions used in python files are written in "sr.h", and "cdef.pyx" include "sr.h" should be built as follows.
'' python setup.py install''
''cython -a cdef.pyx''
''cp build/lib.linux-x86_64-3.7/gym/envs/classic_control/cdef.cpython-37m-x86_64-linux-gnu.so cdef.so''

2. RL training framework is in elegantRL/
''python setup.py install''
''python demo.py''

##  interfaces
iperf_tcp.c is used for normal communication. and we get the sock_fd of connections to set/getsockopt 
