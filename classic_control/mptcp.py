import gym
from gym import spaces
from gym.utils import seeding
import numpy as np
from os import path
import socket
import random as rm
import time 
import matplotlib.pyplot as plt
from setuptools import setup
import cdef
import struct


class MptcpEnv(gym.Env):
    metadata = {
        'render.modes' : ['human', 'rgb_array'],
        'video.frames_per_second' : 30
    }

    def __init__(self):
        
  
        self.state_max = [100,100,100,100,100]
        #self.state_max = [1,1,1,1,1]
        
        #self.path_num = 3
        self.feature_num = 5
        self.alpha = 0.03
        self.beta = 0.05
        self.meta_wq_len = 0
        self.log = {"action":[[],[]],"state":[[],[]],"reward":[[],[]],"cwnd":[[],[],[]],"rtt":[[],[],[]],"retrans":[[],[],[]],"unack":[[],[],[]],"loss":[[],[],[]],"th":[[],[],[]]}
        self.time_start = time.time()
        self.time_pre = time.time()
        self.episode_record = 0
        self.rtt = [0,0]
        self.th = [0,0]
        self.cwnd = [0,0]
        self.retrans =[0,0]
        self.lost = [0,0]
        self.unack = [0,0]
        self.title = ["rtt: ","th:","loss:","unack: ","cwnd: "]
        unix_rcv_sock = cdef.connect_unix()
        (self.sfd,data) = cdef.fjs_recv_fd(unix_rcv_sock)
        
        self.sock = socket.fromfd(self.sfd, socket.AF_INET, socket.SOCK_STREAM,0)
        print(str(self.sock))
        self.sch = "default"
        r = self.sock.setsockopt(6,43,self.sch)
        print("[selected sch:%s\n]"%self.sch)
        time.sleep(10)
        
        self.subflow_num = cdef.getsubflownum(self.sfd)
        print("[subflownum]",self.subflow_num)
        sta_low =np.array([[0,0,0,0,0] for i in range(self.subflow_num)]).reshape(1,self.subflow_num*self.feature_num)[0]
        sta_high = np.array([[1000,100,10,100,100] for i in range(self.subflow_num)]).reshape(1,self.subflow_num*self.feature_num)[0]
        self.observation_space = spaces.Box(low=sta_low,
                                       high=sta_high,
                                       dtype="float32") # [s1p1,s2p1,s3p1,....s3p3]
        self.action_space = spaces.Box(low=np.array([0 for i in range(self.subflow_num)]), high=np.array([1 for i in range(self.subflow_num)]), dtype="float32")
        self.seed()
        self.logfile = open("log.info","a+")
        self.logfile.write("!new exp start!\n")
        self.logfile.write(self.sch)
        for inx in range(self.feature_num):
            self.logfile.write(self.title[inx%self.feature_num])
            self.logfile.write("\t")

        self.logfile.write("\n")
       
    def seed(self, seed=None):
        self.np_random, seed = seeding.np_random(seed)
        return [seed]


    def getnetworkstate(self):
        
        self.state = []
        self.used_state = []
        now = time.time()
        self.time_gap = now - self.time_pre
        self.time_pre = now
        print("time gap",self.time_gap)
        

        # #timestamp = time.clock()-self.time_start
        # #self.log["state"][0].append(timestamp)         # for plot the trend of state and action
        # #self.log["state"][1].append(self.state[1]+self.state[6])
        
        
        
        self.state,state_len = cdef.getstate(self.sfd)
        self.state = self.state[:state_len]
        print("!!!!!!!!!!!\n\nstate:\n\n",self.state,state_len)
        timestamp = time.time()-self.time_start
        self.log["cwnd"][0].append(timestamp)
        self.log["rtt"][0].append(timestamp)
        for inx,item in enumerate(self.state):
            loc = inx / 6 
            if(inx%6==0):
                self.rtt[loc]=item
                self.used_state.append(item)
                self.log["rtt"][loc+1].append(self.rtt[loc])   
            elif(inx%6==1):
                
                cal_th = (item - self.th[loc]) * 8 / self.time_gap
                cal_th /= 1000000
                self.th[loc] = item
                self.used_state.append(cal_th)
                self.log["th"][loc+1].append(cal_th)   
            elif(inx%6==2):
                cal_retrans = item - self.retrans[loc]
                self.retrans[loc] = item
                self.used_state.append(cal_retrans)
                self.log["retrans"][loc+1].append(item)   
            elif(inx%6==3):
                self.unack[loc] = item
                self.used_state.append(item)
                self.log["unack"][loc+1].append(self.unack[loc])   
            elif(inx%6==4):
                self.cwnd[loc] = item
                self.used_state.append(item)
                self.log["cwnd"][loc+1].append(self.cwnd[loc])
            elif(inx%6==5):
                self.lost[loc] = item
                self.log["loss"][loc+1].append(self.lost[loc])   
        
            
           
        self.used_state=np.array(self.used_state)
        for inx,s in enumerate(self.used_state):
            print(self.title[inx%self.feature_num],s)
            #self.logfile.write(self.title[inx%self.feature_num])
            self.logfile.write(str(round(s,2)))
            self.logfile.write("\t")
            if(inx % 4 == 0 and inx != 0):
                self.logfile.write("\n")
        self.logfile.write("\n")
        if self.used_state.shape != self.observation_space.shape:
            print("[getstate]state shape error!")
            self.state = self.state[:len(self.observation_space)]
        self.state = self.used_state
        return self.state

    def setaction(self, u):

            pkt_per_path = []
            ret = 0
            
            # if(self.episode_record == 0):
            #     u = [0.5,0.5]
            # elif(self.episode_record == 1):
            #     u = [0.99,0.01]
            # elif(self.episode_record == 2):
            #     u = [0.01,0.99]
            # else:
            #     u = [0.3,0.7]
            #u = [0.8,0.2]
            #print("u:\n")
            #print(u)
            u = [1,0]
            for u_i in u:
                pkt_per_path.append(round(u_i,2))
                
            
            #pkt_per_path = [0.5,0.5]
            outstr = str(pkt_per_path)[1:-1]
            outstr = outstr.replace(' ','')
            outstr = outstr+","
            i=1
            for i in range(len(outstr)):
                if(i==len(outstr)-1):
                    break
                prev = outstr[i-1]
                now = outstr[i]
                post = outstr[i+1]

                if(prev=='.' and now.isdigit() and post == ','):
                    outstr=outstr[:i+1] + '0' + outstr[i+1:]

            print ("\n[action]:%s\n"%outstr)
            #self.logfile.write("\n[action]:%s\n"%outstr)
            #print("len:action%d\n"%len(outstr))
            timestamp = time.time()-self.time_start
            #self.log["action"][0].append(timestamp)         # for plot the trend of state and action
            #self.log["action"][1].append(u[0]/u[1])
            # ret = self.clientSock.sendall(outstr.encode())           # send to iperf_tcp.c
            #ret = self.sock.setsockopt(6,46,outstr)
            
            return ret

    def step(self,u):        
    
        
        # 1 step : set action
        ret_set = self.setaction(u)
        
        time.sleep(1)         # mean set gap is 0.5ms(cal by client_test),maybe just dont sleep and wait for client 

        # 2 step : get obs state(s_t+1)
        print("\n[state0]get state for calculating reward:\n")
        
        ret_get = self.getnetworkstate()
        
        # if above operation fail, block it.
        # 3 step : cal reward
        sum_th = 0
        sum_rtt_item= 0 
        sum_rtt= 0 
        sum_loss=0
        #ret_get = self.getnetworkstate()
        for i in range(0,self.subflow_num*self.feature_num,self.feature_num):
            #sum_rtt_item += self.state[i]*self.state[1+i]
            sum_rtt += self.state[i]
            sum_th += self.state[1+i]
            sum_loss += self.state[2+i]
        
        
        # if(sum_th != 0):
        #     sum_rtt = sum_rtt_item/sum_th
        
        
        #reward = sum_th - self.alpha*sum_rtt - self.beta * sum_loss
        #reward = sum_th - self.alpha * sum_rtt - self.beta * sum_loss
        reward = sum_th
        reward *= 0.8                  # scale 
        
        timestamp = time.time()-self.time_start

        self.log["reward"][0].append(timestamp)
        self.log["reward"][1].append(reward)  
        self.plot_trend()
        #print("[norm state]%s"%str(self.state))
        print("\n*[norm REWARD]%f\n"%reward)
        self.logfile.write("\n*[norm REWARD]%f\n"%reward)
        #time.sleep(3*0.02)      # each SI = 3-4 RTT
        print("\n[state1]get state at the end of SI:\n")
        #ret_get = self.getnetworkstate()
        
        return self._get_obs(), reward, False, {}
    
    def reset(self):
        #high = np.array([np.pi, 1])
        #self.state = self.np_random.uniform(low=-high, high=high)
        #self.state = self.np_random.uniform(low=0,high = 10000,size = self.feature_num*self.subflow_num)
        #self.state = np.array([20,5,0] * self.subflow_num)
        self.getnetworkstate()
        
        self.last_u = [0.5,0.5]
        return self._get_obs()
    def reset_between_episode(self,u):
        self.getnetworkstate()
        self.last_u = u
        
        return self._get_obs()
    def _get_obs(self):
       
        return np.array(self.state)
   

    def close(self):
        if self.viewer: self.viewer.close()
    def plot_trend(self):
        # action_x = self.log["action"][0]
        # action_y = self.log["action"][1]
        # state_x = self.log["state"][0][:-1]
        # state_y = self.log["state"][1][:-1]
        print("len_time",len(self.log["cwnd"][0]))
        print("len_cwnd",len(self.log["cwnd"][1]))
        reward_x = self.log["reward"][0]
        reward_y = self.log["reward"][1]
        plt.figure(2)
        plt.plot(reward_x, reward_y, color="red")
        #plt.plot(state_x, state_y, color="blue")


        plt.title("reward trend",   fontsize=20)
        plt.xlabel("timestamp", fontsize=12)
        plt.ylabel("reward", fontsize=12)


        plt.tick_params(axis='both', labelsize=10)
        #plt.savefig("/home/cx/trend"+str(self.episode_record)+".png")
        plt.savefig("/home/cx/reward_%s.png"%self.sch)
        
        # #plt.clf()
        # #plt.cla()
        # plt.figure(2)
        # plt.plot(state_x, state_y, color="blue")
        # plt.title("bw",   fontsize=20)
        # plt.xlabel("timestamp", fontsize=12)
        # plt.ylabel("bw", fontsize=12)
        # plt.savefig("/home/cx/bw.png")
        #plt.close()
        #plt.show()
        #self.log = {"action":[[],[]],"state":[[],[]]}
        fig, axs = plt.subplots(4)
        timestamp = self.log["cwnd"][0]
        axs0 = axs[0]
        axs0.cla()
        color0 = ['green','limegreen']
        color1 = ['red','coral']
        color2 = 'blue'
        axs0.set_xlabel('time')
        axs0.set_ylabel('cwnd/unack')
        axs0.plot(timestamp, self.log["cwnd"][1], label='cwnd_4g', color=color0[0])
        axs0.plot(timestamp, self.log["cwnd"][2], label='cwnd_wifi', color=color1[0])
        axs0.plot(timestamp, self.log["unack"][1], label='unack_4g', color=color0[1])
        axs0.plot(timestamp, self.log["unack"][2], label='unack_wifi', color=color1[1])
        #axs0.legend( )
        

        ax11 = axs[1]
        ax11.cla()

        ax11.set_xlabel('time')
        ax11.set_ylabel('rtt/retrans')
        ax11.plot(timestamp, self.log["rtt"][1], label='rtt_4g', color=color0[0])
        ax11.plot(timestamp, self.log["rtt"][2], label='rtt_wifi', color=color1[0])
        #ax11.plot(timestamp, self.log["retrans"][1], label='retranse_4g', color=color0[1])
        #ax11.plot(timestamp, self.log["retrans"][2], label='retranse_wifi', color=color1[1])
        ax11.tick_params(axis='y')
        
        #ax11.axhline(y=1000,c="yellow")
        #ax11.legend( )

        ax2 = axs[2]
        ax2.cla()

        ax2.set_xlabel('time')
        ax2.set_ylabel('th')
        ax2.plot(timestamp, self.log["th"][1], label='th_4g', color=color0[0])
        ax2.plot(timestamp, self.log["th"][2], label='th_wifi', color=color1[0])
        
        ax2.tick_params(axis='y')
        

        ax3 = axs[3]
        ax3.cla()

        ax3.set_xlabel('time')
        ax3.set_ylabel('loss')

        ax3.plot(timestamp, self.log["loss"][1], label='loss_4g', color=color0[1])
        ax3.plot(timestamp, self.log["loss"][2], label='loss_wifi', color=color1[1])
        ax3.tick_params(axis='y')
        
        #ax2.legend( )

        '''plot save'''
        
        plt.savefig("/home/cx/exp-mptcp/networkstate_%s_%s.png"%(self.sch,str(round(self.time_start,2))))
        plt.close('all')  # avoiding warning about too many open figures, rcParam `figure.max_open_warning`
        # plt.show()  # if use `mpl.use('Agg')` to draw figures without GUI, then plt can't plt.show()

        self.episode_record += 1



def getnetworkstate_test():
    # fix me!
    # ret = self.sock.getSocket(self.state)
    # if ret == -1:
    #    return -1

    data = "[22.4,12.4,42,2,22,44,100,]"
    state_temp =[]
    print('[Received]', data)
    if data[0] != '[':
        return -1
    else:
        temp = ""
        for i in range(len(data)):
            if (data[i] >= '0' and data[i] <= '9') or data[i] == '.':
                temp += data[i]
            else:
                if temp != "":
                    state_temp.append(float(temp))
                    temp=""
    state = np.array(state_temp)[:-1]
    meta_wq_len = state_temp
    print("[state]%s"  % state)
    return 0


def setaction_test(u):
    # reshape u to integer
    pkt_per_path = []

    for u_i in u:
        pkt_per_path.append(int(100 * u_i))  # [2,3,8,0]

    

    print(pkt_per_path)
    return 0

if __name__ == '__main__':
    
    env = gym.make('Mptcp-v0')

    