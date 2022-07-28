#ifndef RDMA_HW_H
#define RDMA_HW_H

#include <ns3/rdma.h>
#include <ns3/rdma-queue-pair.h>
#include <ns3/node.h>
#include <ns3/custom-header.h>
#include "qbb-net-device.h"
#include <unordered_map>
#include "pint.h"

namespace ns3 {

struct RdmaInterfaceMgr{		//RDMA Interface Manager : RDMA接口管理器
	
	Ptr<QbbNetDevice> dev;
	Ptr<RdmaQueuePairGroup> qpGrp;
	
	RdmaInterfaceMgr() : dev(NULL), qpGrp(NULL) {}
	RdmaInterfaceMgr(Ptr<QbbNetDevice> _dev){
		dev = _dev;
	}
};


/******************************
 *
 * Gimbal
 *
 * ****************************/
//保存延迟和延迟阈值
struct Latency_congestion{	//spdk_nvmf_tmgr_lat_cong
	//使用EWMA测出的当前延迟
	uint64_t Lat_ewma;			

	//论文3.3Rate Control Engine介绍的3个延迟阈值（latency thresholds）
	uint64_t Thresh_cur;
	uint64_t Thresh_min;
	uint64_t Thresh_max;
	uint64_t Thresh_residue;
};
//保存速率相关信息
struct Rate{						//spdk_nvmf_tmgr_rate
	uint64_t target_rate;			//令牌生成速率，单位是Byte/s,范围是50MB/S~4GB/S

	uint64_t cpl_rate;
	uint64_t cpl_bytes;				//用于计数，每传输超过16MB数据，更新一次cpl_rate
	uint32_t last_cpl_rate_update_time;

	//uint64_t write_tokens;
	//uint64_t read_tokens;
	uint64_t token;
	uint64_t max_bucket_size;		//令牌桶的最大容量（初始化为256kb）
	uint32_t last_refill_time;

	//int64_t write_cost;				
};	

struct traffic_manager{

	Latency_congestion cong;		//目前只考虑读，不考虑写

	Rate rate;

	int64_t write_cost;				//写入成本,范围是1kb,9kb之间，1kb代表读写花费相同
};


class RdmaHw : public Object {
public:


	/******************************
	 *
	 * Gimbal
	 *
	 * ****************************/
	//Latency_congestion m_cong;
	//Rate m_rate;
	traffic_manager m_tmgr;

	void Gimbal_test();

	//初始化
	void Gimbal_init();
	//初始化m_cong
	void Gimbal_cong_init();
	//初始化m_rate
	void Gimbal_rate_init();


	//根据延迟，判断拥塞状态
	int	Gimbal_cong_update(uint32_t latency);
	//
	void Gimbal_cong_submit();
	//根据拥塞状态，调整目标速率target_rate
	void Gimbal_cong_complete(uint32_t payload_size,uint32_t latency);
	

	//生成令牌
	void Gimbal_rate_bucket_refill();
	//判断是否有足够的令牌给当前的io请求,如果有，可以提交请求
	int Gimbal_rate_is_submittable(uint32_t payload_size);
	//根据请求的读写类型，发放相应的令牌
	void Gimbal_rate_submit(uint32_t payload_size);
	//更新completion_rate
	void Gimbal_rate_complete(uint32_t payload_size);


	//更新write_cost
	//void Gimbal_set_write_cost(uint64_t write_cost);
	//void Gimbal_update_write_cost(struct Latency_congestion *cong);



	static TypeId GetTypeId (void);
	RdmaHw();

	Ptr<Node> m_node;
	DataRate m_minRate;		//< Min sending rate
	uint32_t m_mtu;
	uint32_t m_cc_mode;		//---------------这个用来指定使用的拥塞控制算法，m_cc_mode=1代表DCQCN算法-----------------------------
	double m_nack_interval;
	uint32_t m_chunk;
	uint32_t m_ack_interval;
	bool m_backto0;
	bool m_var_win, m_fast_react;
	bool m_rateBound;
	std::vector<RdmaInterfaceMgr> m_nic; // list of running nic controlled by this RdmaHw
	std::unordered_map<uint64_t, Ptr<RdmaQueuePair> > m_qpMap; // mapping from uint64_t to qp
	std::unordered_map<uint64_t, Ptr<RdmaRxQueuePair> > m_rxQpMap; // mapping from uint64_t to rx qp
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// qp complete callback
	typedef Callback<void, Ptr<RdmaQueuePair> > QpCompleteCallback;
	QpCompleteCallback m_qpCompleteCallback;

	void SetNode(Ptr<Node> node);
	void Setup(QpCompleteCallback cb); // setup shared data and callbacks with the QbbNetDevice
	static uint64_t GetQpKey(uint32_t dip, uint16_t sport, uint16_t pg); // get the lookup key for m_qpMap
	Ptr<RdmaQueuePair> GetQp(uint32_t dip, uint16_t sport, uint16_t pg); // get the qp
	uint32_t GetNicIdxOfQp(Ptr<RdmaQueuePair> qp); // get the NIC index of the qp
	void AddQueuePair(uint64_t size, uint16_t pg, Ipv4Address _sip, Ipv4Address _dip, uint16_t _sport, uint16_t _dport, uint32_t win, uint64_t baseRtt, Callback<void> notifyAppFinish); // add a new qp (new send)
	void DeleteQueuePair(Ptr<RdmaQueuePair> qp);

	Ptr<RdmaRxQueuePair> GetRxQp(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg, bool create); // get a rxQp
	uint32_t GetNicIdxOfRxQp(Ptr<RdmaRxQueuePair> q); // get the NIC index of the rxQp
	void DeleteRxQp(uint32_t dip, uint16_t pg, uint16_t dport);

	int ReceiveUdp(Ptr<Packet> p, CustomHeader &ch);
	int ReceiveCnp(Ptr<Packet> p, CustomHeader &ch);
	int ReceiveAck(Ptr<Packet> p, CustomHeader &ch); // handle both ACK and NACK
	int Receive(Ptr<Packet> p, CustomHeader &ch); // callback function that the QbbNetDevice should use when receive packets. Only NIC can call this function. And do not call this upon PFC

	void CheckandSendQCN(Ptr<RdmaRxQueuePair> q);
	int ReceiverCheckSeq(uint32_t seq, Ptr<RdmaRxQueuePair> q, uint32_t size);
	void AddHeader (Ptr<Packet> p, uint16_t protocolNumber);
	static uint16_t EtherToPpp (uint16_t protocol);

	void RecoverQueue(Ptr<RdmaQueuePair> qp);
	void QpComplete(Ptr<RdmaQueuePair> qp);
	void SetLinkDown(Ptr<QbbNetDevice> dev);

	// call this function after the NIC is setup
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	void RedistributeQp();

	Ptr<Packet> GetNxtPacket(Ptr<RdmaQueuePair> qp); // get next packet to send, inc snd_nxt
	void PktSent(Ptr<RdmaQueuePair> qp, Ptr<Packet> pkt, Time interframeGap);
	void UpdateNextAvail(Ptr<RdmaQueuePair> qp, Time interframeGap, uint32_t pkt_size);
	void ChangeRate(Ptr<RdmaQueuePair> qp, DataRate new_rate);


	/******************************
	 * Mellanox's version of DCQCN
	 *****************************/
	double m_g; //feedback weight
	double m_rateOnFirstCNP; // the fraction of line rate to set on first CNP
	bool m_EcnClampTgtRate;
	double m_rpgTimeReset;
	double m_rateDecreaseInterval;
	uint32_t m_rpgThreshold;
	double m_alpha_resume_interval;
	DataRate m_rai;		//< Rate of additive increase
	DataRate m_rhai;		//< Rate of hyper-additive increase

	// the Mellanox's version of alpha update:
	// every fixed time slot, update alpha.
	void UpdateAlphaMlx(Ptr<RdmaQueuePair> q);
	void ScheduleUpdateAlphaMlx(Ptr<RdmaQueuePair> q);

	// Mellanox's version of CNP receive
	void cnp_received_mlx(Ptr<RdmaQueuePair> q);

	// Mellanox's version of rate decrease
	// It checks every m_rateDecreaseInterval if CNP arrived (m_decrease_cnp_arrived).
	// If so, decrease rate, and reset all rate increase related things
	void CheckRateDecreaseMlx(Ptr<RdmaQueuePair> q);
	void ScheduleDecreaseRateMlx(Ptr<RdmaQueuePair> q, uint32_t delta);

	// Mellanox's version of rate increase
	void RateIncEventTimerMlx(Ptr<RdmaQueuePair> q);
	void RateIncEventMlx(Ptr<RdmaQueuePair> q);
	void FastRecoveryMlx(Ptr<RdmaQueuePair> q);
	void ActiveIncreaseMlx(Ptr<RdmaQueuePair> q);
	void HyperIncreaseMlx(Ptr<RdmaQueuePair> q);

	/***********************
	 * High Precision CC
	 ***********************/
	double m_targetUtil;
	double m_utilHigh;
	uint32_t m_miThresh;
	bool m_multipleRate;
	bool m_sampleFeedback; // only react to feedback every RTT, or qlen > 0
	void HandleAckHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	void UpdateRateHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
	void UpdateRateHpTest(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
	void FastReactHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/**********************
	 * TIMELY
	 *********************/
	double m_tmly_alpha, m_tmly_beta;
	uint64_t m_tmly_TLow, m_tmly_THigh, m_tmly_minRtt;
	void HandleAckTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	void UpdateRateTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool us);
	void FastReactTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/**********************
	 * DCTCP
	 *********************/
	DataRate m_dctcp_rai;
	void HandleAckDctcp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/*********************
	 * HPCC-PINT
	 ********************/
	uint32_t pint_smpl_thresh;
	void SetPintSmplThresh(double p);
	void HandleAckHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	void UpdateRateHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
};

} /* namespace ns3 */

#endif /* RDMA_HW_H */
