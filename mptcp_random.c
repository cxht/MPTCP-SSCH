/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>
#include <trace/events/tcp.h>
#include <linux/init.h>
#include <linux/kernel.h>

static unsigned char start = 0;
static unsigned max_sk = 1;
static int ratio_after[16];
static int len_after;
static int weight[16];
void get_random_bytes(void *buf, int nbytes);
 
static unsigned long get_random_number(void)
{
    u8 randNum;
	int i = 0;
    get_random_bytes(&randNum, 1);
    return randNum;
}



struct randomsched_priv {
	u32	last_rbuf_opti;
};

static struct randomsched_priv *randomsched_get_priv(const struct tcp_sock *tp)
{
	return (struct randomsched_priv *)&tp->mptcp->mptcp_sched[0];
}

int random_char2float100(char *optval,int *array,int len_opt, int *len_array)
{
	char tmp[16];
	int i =0;
	int tmp_inx = 0;
	int float_len = 0;
	int dot = 0;
	
	char now ;
	for(;i<len_opt;i++)
	{
		now = *(optval+i);
		if((now == '.')||((now >= '0')&&(now <= '9')))
		{
			*(tmp+tmp_inx++) = *(optval+i);
			if(*(optval+i)=='.')
			{
				dot = tmp_inx-1;
			}
		}		
		else if(now==',')
		{
			int f = 0;
			
			char *end = '\0';
			tmp[tmp_inx] = '\0';
			
			if(tmp[0]=='1')
			{	
				f = 100;			//%100
				
			}

			else if(tmp[0]=='0')
			{
					
				f = simple_strtoul(tmp+dot+1, &end, 10);
			}
			else
			{
				break;
			}
			tmp_inx = 0;
			dot = 0;

			//*(array+float_len++)=simple_strtoul(tmp, &end, 10);
			*(array+float_len++)=f;
			f=0;
			memset(tmp,0,sizeof(tmp));
		}
		else{
			break;
		}
	}
	*len_array = float_len;
}



int random_mptcp_set_weight(struct sock *sk, char *ratio,int len_ratio)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct mptcp_tcp_sock *mptcp;
	int i = 0;
	
				//if change to float, modify here!
	
	int pre = 0;
	int now = 0;
	//pr_info("meta_len %d \n", meta_write_qlen);
	
	random_char2float100(ratio,ratio_after,len_ratio,&len_after);	//reshape ratio to int[]
	
	for(;i<len_after;i++)
	{
		now = (int)((ratio_after[i] * 256) / 100);		//exp. 68/100 = 0.68 *  len = 6.8
		weight[i] = now + pre;
		pre = weight[i];
		//pr_info("[weight]%d:%d\n",i,weight[i]);
	}
	
	return 0;
}



bool random_mptcp_is_def_unavailable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (tp->pf)
		return true;

	return false;
}


static bool random_mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	mss_now = tcp_current_mss(sk);

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * mss_now;

	if (tp->write_seq - tp->snd_nxt >= space)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* Is the sub-socket sk available to send the skb? */
bool random_mptcp_is_available(struct sock *sk, const struct sk_buff *skb,
			bool zero_wnd_test)
{
	return !random_mptcp_is_def_unavailable(sk) &&
	       !random_mptcp_is_temp_unavailable(sk, skb, zero_wnd_test);
}


/* Are we not allowed to reinject this skb on tp? */
static int random_mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

bool random_subflow_is_backup(const struct tcp_sock *tp)
{
	return tp->mptcp->rcv_low_prio || tp->mptcp->low_prio;
}


bool random_subflow_is_active(const struct tcp_sock *tp)
{
	return !tp->mptcp->rcv_low_prio && !tp->mptcp->low_prio;
}


/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*random_get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *bestsk = NULL;
	u32 min_srtt = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	struct mptcp_tcp_sock *mptcp;
	int seed = get_random_number();
	int selected_path = 0;
	int iter = 0;
	int i = 0;

	for(i=0;i<len_after;i++)
	{
		if(seed<weight[i])
		{
			selected_path = i;
			break;
		}
	}


	mptcp_for_each_sub(mpcb, mptcp) {
		
		
		
	
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		bool unused = false;

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
		{
			iter++;
			continue;
		}
		if (!random_mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused){
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			iter++;
			continue;
		
		}

		if (random_mptcp_is_def_unavailable(sk))
		{
			iter++;
			continue;
		}
		if (random_mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
			iter++;
			continue;
		}

		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_srtt = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		if(iter == selected_path)
		{
			
			bestsk = sk;
			//pr_info("best path:%d",iter);
		}

		// if (tp->srtt_us < min_srtt) {
		// 	min_srtt = tp->srtt_us;
		// 	bestsk = sk;
		// }
		iter++;
	}
	
	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

	return bestsk;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
struct sock *random_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
				   bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	bool looping = false, force;
	
	struct mptcp_tcp_sock *mptcp;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		

		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);

			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    random_mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
restart:
	
	sk = random_get_subflow_from_selectors(mpcb, skb, &random_subflow_is_active,
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = random_get_subflow_from_selectors(mpcb, skb, &random_subflow_is_backup,
					zero_wnd_test, &force);
	if (!force && skb) {
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;

		if (!looping) {
			looping = true;
			goto restart;
		}
	}
	return sk;
}


static struct sk_buff *random_mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb_head;
	struct randomsched_priv *random_p = randomsched_get_priv(tp);

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_rtx_queue_head(meta_sk);

	if (!skb_head)
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_jiffies32 - random_p->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

	/* Half the cwnd of the slow flows */
	mptcp_for_each_sub(tp->mpcb, mptcp) {
		struct tcp_sock *tp_it = mptcp->tp;

		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				random_p->last_rbuf_opti = tcp_jiffies32;
			}
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_sub(tp->mpcb, mptcp) {
			struct tcp_sock *tp_it = mptcp->tp;

			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt_us >= tp_it->srtt_us) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && random_mptcp_is_available(sk, skb_head, false)) {
			trace_mptcp_retransmit(sk, skb_head);
			return skb_head;
		}
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = random_get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = random_mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *mptcp_random_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now, in_flight_space;
	int remaining_in_flight_space;
	u32 max_len, max_segs, window;
	struct tcp_sock *subtp;
	u16 gso_max_segs;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = random_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = random_mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

	/* max_len is what would fit in the cwnd (respecting the 2GSO-limit of
	 * tcp_cwnd_test), but ignoring whatever was already queued.
	 */
	max_len = min(mss_now * max_segs, skb->len);

	in_flight_space = (subtp->snd_cwnd - tcp_packets_in_flight(subtp)) * mss_now;
	remaining_in_flight_space = (int)in_flight_space - (subtp->write_seq - subtp->snd_nxt);

	if (remaining_in_flight_space <= 0)
		WARN_ONCE(1, "in_flight %u cwnd %u wseq %u snxt %u mss_now %u cache %u",
			  tcp_packets_in_flight(subtp), subtp->snd_cwnd,
			  subtp->write_seq, subtp->snd_nxt, mss_now, subtp->mss_cache);
	else
		/* max_len now fits exactly in the write-queue, taking into
		 * account what was already queued.
		 */
		max_len = min_t(u32, max_len, remaining_in_flight_space);

	window = tcp_wnd_end(subtp) - subtp->write_seq;

	/* max_len now also respects the announced receive-window */
	max_len = min(max_len, window);

	*limit = max_len;

	return skb;
}

static void randomsched_init(struct sock *sk)
{
	struct randomsched_priv *random_p = randomsched_get_priv(tcp_sk(sk));

	random_p->last_rbuf_opti = tcp_jiffies32;
}

static struct mptcp_sched_ops mptcp_sched_random = {
	.get_subflow = random_get_available_subflow,
	.next_segment = mptcp_random_next_segment,
	.name = "random",
	.owner = THIS_MODULE,
};


static int __init random_register(void)
{
	BUILD_BUG_ON(sizeof(struct randomsched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_random))
		return -1;

	return 0;
}

static void random_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_random);
}


module_init(random_register);
module_exit(random_unregister);

MODULE_AUTHOR("Cx");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("random MPTCP");
MODULE_VERSION("0.95");
