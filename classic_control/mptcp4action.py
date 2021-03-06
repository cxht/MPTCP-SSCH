import gym
from gym import spaces
from gym.utils import seeding
import numpy as np
from os import path
from ctypes import *
import socket
import random as rm
import time 
import matplotlib.pyplot as plt

class MptcpEnv4(gym.Env):
    metadata = {
        'render.modes' : ['human', 'rgb_array'],
        'video.frames_per_second' : 30
    }

    def __init__(self):
        
  
        self.state_max = [100,10000,100,100,100]
        #self.state_max = [1,1,1,1,1]
        
        #self.path_num = 3
        self.feature_num = 5
        self.alpha = 0.03
        self.beta = 0.05
        self.meta_wq_len = 0
        self.r_mu = 0
        self.r_std = 1
        
        self.log = {"action":[[],[]],"state":[[],[]],"reward":[[],[]]}
        self.time_start = time.clock()
        self.episode_record = 0

        self.address_server = ('127.0.0.1', 12345)

        self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.clientSock.connect(self.address_server)  #

        except Exception:
            print('[!] Server not found ot not open')
            exit(-1)
       
        print("connect success!\n")
        
        self.tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.address_local = ("0.0.0.0", 12346)
        self.tcpSock.bind(self.address_local)

        self.tcpSock.listen(20)

        self.conn, self.addr = self.tcpSock.accept()  #

        print('[+] Connected with', self.addr)
        
        x = self.conn.recv(1)      # client socket get from client for init action space size
        print("subflow num :%s\n"%x)
        
        
        self.subflow_num = int(str(x.decode()))           # subflows number
        
        sta_low =np.array([[0,0,0,0,0] for i in range(self.subflow_num)]).reshape(1,self.subflow_num*self.feature_num)[0]
        sta_high = np.array([[1000,30000,10,100,100] for i in range(self.subflow_num)]).reshape(1,self.subflow_num*self.feature_num)[0]
        self.observation_space = spaces.Box(low=sta_low,
                                       high=sta_high,
                                       dtype="float32") # [s1p1,s2p1,s3p1,....s3p3]
        #self.action_space = spaces.Box(low=np.array([0 for i in range(self.subflow_num)]), high=np.array([1 for i in range(self.subflow_num)]), dtype="float32")
        self.action_space = spaces.Discrete(4)
        self.seed()


    def seed(self, seed=None):
        self.np_random, seed = seeding.np_random(seed)
        return [seed]
    
    def fix_r_scale(self, r_mu,r_std):
        self.r_mu = r_mu
        self.r_std= r_std  

    def getnetworkstate(self):
        self.title = ["rtt: ","th:  ","loss:    ","unack:   ","cwnd:    "]
        self.state = []
        state_temp = []
        state_group = []
        data = self.conn.recv(1024)  
        #print('[Received]', data)

        start = data.find('[')
        if start == -1:
            return -1
        else:
            temp = ""
            for j in range(len(data)):
                if(data[j]=="["):
                    # if(data[j:].find(']') == -1):
                    #     break
                    start = j
                    break
            
            i = start
            for i in range(start,len(data)):
                if(data[i:].find(']') == -1):
                    break
                if (data[i]>='0' and data[i]<='9') or data[i]=='.':
                    temp+=data[i]
                elif (data[i]==','):
                    if temp!="":
                        state_temp.append(float(temp))
                        temp = ""
                elif (data[i]=='['):
                    continue
                elif (data[i] == ']'):
                    state_group.append(np.array(state_temp))
                    state_temp = []
                    
        state_group = state_group[-3:]          # average 
        #print(state_group)
        for item in zip(*state_group):
            self.state.append(sum(item)/len(item))

        for inx,item in enumerate(self.state):
            self.state[inx] = item/self.state_max[inx%self.feature_num]                #normalized
        
        self.state = np.array(self.state)
        
        # for inx,s in enumerate(self.state):
        #     print(self.title[inx%self.feature_num],s)
        #timestamp = time.clock()-self.time_start
        #self.log["state"][0].append(timestamp)         # for plot the trend of state and action
        #self.log["state"][1].append(self.state[1]+self.state[6])
        if self.state.shape != self.observation_space.shape:
            print("[getstate]state shape error!")
            self.state = self.state[:len(self.observation_space)]
        return self.state

    def setaction(self, u):

            pkt_per_path = []
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
            for u_i in u:
                pkt_per_path.append(round(u_i,2))
                
            
            print(u,"\n")
            pkt_per_path = [0.5,0.5]
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
            #print("len:action%d\n"%len(outstr))
            timestamp = time.clock()-self.time_start
            #self.log["action"][0].append(timestamp)         # for plot the trend of state and action
            #self.log["action"][1].append(u[0]/u[1])
            ret = self.clientSock.sendall(outstr.encode())           # send to iperf_tcp.c
            
            
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
            sum_rtt_item += self.state[i]*self.state[1+i]
            sum_th += self.state[1+i]
            sum_loss += self.state[2+i]
        
        
        if(sum_th != 0):
            sum_rtt = sum_rtt_item/sum_th
        
        
        #reward = sum_th - self.alpha*sum_rtt - self.beta * sum_loss
        reward = sum_th - self.alpha*sum_rtt - self.beta * sum_loss
        
        #reward = (reward-self.r_mu)/self.r_std                  # scale 
        
        timestamp = time.clock()-self.time_start
        self.log["reward"][0].append(timestamp)
        self.log["reward"][1].append(reward)  
        #print("[norm state]%s"%str(self.state))
        print("\n*[norm REWARD]%f\n"%reward)
        
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
        self.last_u = 1
        return self._get_obs()
    def reset_between_episode(self,u):
        self.getnetworkstate()
        self.last_u = u
        self.plot_trend()
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
        reward_x = self.log["reward"][0]
        reward_y = self.log["reward"][1]
        plt.figure(1)
        plt.plot(reward_x, reward_y, color="red")
        #plt.plot(state_x, state_y, color="blue")


        plt.title("reward trend",   fontsize=20)
        plt.xlabel("timestamp", fontsize=12)
        plt.ylabel("reward", fontsize=12)


        plt.tick_params(axis='both', labelsize=10)
        #plt.savefig("/home/cx/trend"+str(self.episode_record)+".png")
        plt.savefig("/home/cx/reward.png")
        
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

    