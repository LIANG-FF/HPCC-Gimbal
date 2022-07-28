#include <ns3/simulator.h>
#include <ns3/seq-ts-header.h>
#include <ns3/udp-header.h>
#include <ns3/ipv4-header.h>
#include "ns3/ppp-header.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/data-rate.h"
#include "ns3/pointer.h"
#include "rdma-hw.h"
#include "ppp-header.h"
#include "qbb-header.h"
#include "cn-header.h"

namespace ns3{

TypeId RdmaHw::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::RdmaHw")
		.SetParent<Object> ()								//声明该类的基类
		.AddAttribute("MinRate",							//要绑定的字符串
				"Minimum rate of a throttled flow",			//对上面字符串的解释
				DataRateValue(DataRate("100Mb/s")),			//提供默认值100Mb/s
				MakeDataRateAccessor(&RdmaHw::m_minRate),	//要绑定的变量
				MakeDataRateChecker())						//提供checker检查设置的合法性
		.AddAttribute("Mtu",
				"Mtu.",
				UintegerValue(1000),
				MakeUintegerAccessor(&RdmaHw::m_mtu),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute ("CcMode",
				"which mode of DCQCN is running",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_cc_mode),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("NACK Generation Interval",
				"The NACK Generation interval",
				DoubleValue(500.0),
				MakeDoubleAccessor(&RdmaHw::m_nack_interval),
				MakeDoubleChecker<double>())
		.AddAttribute("L2ChunkSize",
				"Layer 2 chunk size. Disable chunk mode if equals to 0.",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_chunk),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("L2AckInterval",
				"Layer 2 Ack intervals. Disable ack if equals to 0.",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_ack_interval),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("L2BackToZero",
				"Layer 2 go back to zero transmission.",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_backto0),
				MakeBooleanChecker())
		.AddAttribute("EwmaGain",
				"Control gain parameter which determines the level of rate decrease",
				DoubleValue(1.0 / 16),
				MakeDoubleAccessor(&RdmaHw::m_g),
				MakeDoubleChecker<double>())
		.AddAttribute ("RateOnFirstCnp",
				"the fraction of rate on first CNP",
				DoubleValue(1.0),
				MakeDoubleAccessor(&RdmaHw::m_rateOnFirstCNP),
				MakeDoubleChecker<double> ())
		.AddAttribute("ClampTargetRate",
				"Clamp target rate.",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_EcnClampTgtRate),
				MakeBooleanChecker())
		.AddAttribute("RPTimer",
				"The rate increase timer at RP in microseconds",
				DoubleValue(1500.0),
				MakeDoubleAccessor(&RdmaHw::m_rpgTimeReset),
				MakeDoubleChecker<double>())
		.AddAttribute("RateDecreaseInterval",
				"The interval of rate decrease check",
				DoubleValue(4.0),
				MakeDoubleAccessor(&RdmaHw::m_rateDecreaseInterval),
				MakeDoubleChecker<double>())
		.AddAttribute("FastRecoveryTimes",
				"The rate increase timer at RP",
				UintegerValue(5),
				MakeUintegerAccessor(&RdmaHw::m_rpgThreshold),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("AlphaResumInterval",
				"The interval of resuming alpha",
				DoubleValue(55.0),
				MakeDoubleAccessor(&RdmaHw::m_alpha_resume_interval),
				MakeDoubleChecker<double>())
		.AddAttribute("RateAI",
				"Rate increment unit in AI period",
				DataRateValue(DataRate("5Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_rai),
				MakeDataRateChecker())
		.AddAttribute("RateHAI",
				"Rate increment unit in hyperactive AI period",
				DataRateValue(DataRate("50Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_rhai),
				MakeDataRateChecker())
		.AddAttribute("VarWin",
				"Use variable window size or not",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_var_win),
				MakeBooleanChecker())
		.AddAttribute("FastReact",
				"Fast React to congestion feedback",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_fast_react),
				MakeBooleanChecker())
		.AddAttribute("MiThresh",
				"Threshold of number of consecutive AI before MI",
				UintegerValue(5),
				MakeUintegerAccessor(&RdmaHw::m_miThresh),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("TargetUtil",
				"The Target Utilization of the bottleneck bandwidth, by default 95%",
				DoubleValue(0.95),
				MakeDoubleAccessor(&RdmaHw::m_targetUtil),
				MakeDoubleChecker<double>())
		.AddAttribute("UtilHigh",
				"The upper bound of Target Utilization of the bottleneck bandwidth, by default 98%",
				DoubleValue(0.98),
				MakeDoubleAccessor(&RdmaHw::m_utilHigh),
				MakeDoubleChecker<double>())
		.AddAttribute("RateBound",
				"Bound packet sending by rate, for test only",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_rateBound),
				MakeBooleanChecker())
		.AddAttribute("MultiRate",
				"Maintain multiple rates in HPCC",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_multipleRate),
				MakeBooleanChecker())
		.AddAttribute("SampleFeedback",
				"Whether sample feedback or not",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_sampleFeedback),
				MakeBooleanChecker())
		.AddAttribute("TimelyAlpha",
				"Alpha of TIMELY",
				DoubleValue(0.875),
				MakeDoubleAccessor(&RdmaHw::m_tmly_alpha),
				MakeDoubleChecker<double>())
		.AddAttribute("TimelyBeta",
				"Beta of TIMELY",
				DoubleValue(0.8),
				MakeDoubleAccessor(&RdmaHw::m_tmly_beta),
				MakeDoubleChecker<double>())
		.AddAttribute("TimelyTLow",
				"TLow of TIMELY (ns)",
				UintegerValue(50000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_TLow),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("TimelyTHigh",
				"THigh of TIMELY (ns)",
				UintegerValue(500000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_THigh),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("TimelyMinRtt",
				"MinRtt of TIMELY (ns)",
				UintegerValue(20000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_minRtt),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("DctcpRateAI",
				"DCTCP's Rate increment unit in AI period",
				DataRateValue(DataRate("1000Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_dctcp_rai),
				MakeDataRateChecker())
		.AddAttribute("PintSmplThresh",
				"PINT's sampling threshold in rand()%65536",
				UintegerValue(65536),
				MakeUintegerAccessor(&RdmaHw::pint_smpl_thresh),
				MakeUintegerChecker<uint32_t>())
		/******************************
		 *
		 * Gimbal
		 *
		 * ****************************/
		// .AddAttribute("Lat_ewma",
		// 		"使用EWMA计算出的当前延迟",
		// 		UintegerValue(0),
		// 		MakeUintegerAccessor(&RdmaHw::Lat_ewma),
		// 		MakeUintegerChecker<uint64_t>())
		// .AddAttribute("Thresh_cur",
		// 		"latency thresholds",
		// 		UintegerValue(0),
		// 		MakeUintegerAccessor(&RdmaHw::Thresh_cur),
		// 		MakeUintegerChecker<uint64_t>())
		// .AddAttribute("Thresh_min",
		// 		"latency thresholds",
		// 		UintegerValue(0),
		// 		MakeUintegerAccessor(&RdmaHw::Thresh_min),
		// 		MakeUintegerChecker<uint64_t>())
		// .AddAttribute("Thresh_max",
		// 		"latency thresholds",
		// 		UintegerValue(0),
		// 		MakeUintegerAccessor(&RdmaHw::Thresh_max),
		// 		MakeUintegerChecker<uint64_t>())												
		;
	return tid;
}

RdmaHw::RdmaHw(){
}

void RdmaHw::SetNode(Ptr<Node> node){
	m_node = node;
}

//设置网卡 设备/队列 共享数据 和回调函数
void RdmaHw::Setup(QpCompleteCallback cb){
	for (uint32_t i = 0; i < m_nic.size(); i++){	//遍历每一个网卡
		Ptr<QbbNetDevice> dev = m_nic[i].dev;
		if (dev == NULL)
			continue;
		// share data with NIC
		dev->m_rdmaEQ->m_qpGrp = m_nic[i].qpGrp;	//Egress Queue 
		//设置回调函数
		dev->m_rdmaReceiveCb = MakeCallback(&RdmaHw::Receive, this);
		dev->m_rdmaLinkDownCb = MakeCallback(&RdmaHw::SetLinkDown, this);
		dev->m_rdmaPktSent = MakeCallback(&RdmaHw::PktSent, this);
		// config NIC
		dev->m_rdmaEQ->m_rdmaGetNxtPkt = MakeCallback(&RdmaHw::GetNxtPacket, this);
	}
	// setup qp complete callback
	m_qpCompleteCallback = cb;
}

//获取qp对应的网卡索引
uint32_t RdmaHw::GetNicIdxOfQp(Ptr<RdmaQueuePair> qp){
	auto &v = m_rtTable[qp->dip.Get()];
	if (v.size() > 0){
		return v[qp->GetHash() % v.size()];
	}else{
		NS_ASSERT_MSG(false, "We assume at least one NIC is alive");
	}
}
uint64_t RdmaHw::GetQpKey(uint32_t dip, uint16_t sport, uint16_t pg){
	return ((uint64_t)dip << 32) | ((uint64_t)sport << 16) | (uint64_t)pg;
}
Ptr<RdmaQueuePair> RdmaHw::GetQp(uint32_t dip, uint16_t sport, uint16_t pg){
	uint64_t key = GetQpKey(dip, sport, pg);
	auto it = m_qpMap.find(key);
	if (it != m_qpMap.end())
		return it->second;
	return NULL;
}
//在queue pair group中添加一个qp（添加一个流）
void RdmaHw::AddQueuePair(uint64_t size, uint16_t pg, Ipv4Address sip, Ipv4Address dip, uint16_t sport, uint16_t dport, uint32_t win, uint64_t baseRtt, Callback<void> notifyAppFinish){
	// create qp
	Ptr<RdmaQueuePair> qp = CreateObject<RdmaQueuePair>(pg, sip, dip, sport, dport);
	qp->SetSize(size);
	qp->SetWin(win);
	qp->SetBaseRtt(baseRtt);
	qp->SetVarWin(m_var_win);
	qp->SetAppNotifyCallback(notifyAppFinish);

	// add qp
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	m_nic[nic_idx].qpGrp->AddQp(qp);
	uint64_t key = GetQpKey(dip.Get(), sport, pg);
	m_qpMap[key] = qp;

	// set init variables
	DataRate m_bps = m_nic[nic_idx].dev->GetDataRate();
	qp->m_rate = m_bps;
	qp->m_max_rate = m_bps;
	if (m_cc_mode == 1){
		qp->mlx.m_targetRate = m_bps;
	}else if (m_cc_mode == 3){
		qp->hp.m_curRate = m_bps;
		if (m_multipleRate){
			for (uint32_t i = 0; i < IntHeader::maxHop; i++)
				qp->hp.hopState[i].Rc = m_bps;
		}
	}else if (m_cc_mode == 7){
		qp->tmly.m_curRate = m_bps;
	}else if (m_cc_mode == 10){
		qp->hpccPint.m_curRate = m_bps;
	}

	// Notify Nic
	m_nic[nic_idx].dev->NewQp(qp);
}

void RdmaHw::DeleteQueuePair(Ptr<RdmaQueuePair> qp){
	// remove qp from the m_qpMap
	uint64_t key = GetQpKey(qp->dip.Get(), qp->sport, qp->m_pg);
	m_qpMap.erase(key);
}

Ptr<RdmaRxQueuePair> RdmaHw::GetRxQp(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg, bool create){
	uint64_t key = ((uint64_t)dip << 32) | ((uint64_t)pg << 16) | (uint64_t)dport;
	auto it = m_rxQpMap.find(key);
	if (it != m_rxQpMap.end())
		return it->second;
	if (create){
		// create new rx qp
		Ptr<RdmaRxQueuePair> q = CreateObject<RdmaRxQueuePair>();
		// init the qp
		q->sip = sip;
		q->dip = dip;
		q->sport = sport;
		q->dport = dport;
		q->m_ecn_source.qIndex = pg;
		// store in map
		m_rxQpMap[key] = q;
		return q;
	}
	return NULL;
}
uint32_t RdmaHw::GetNicIdxOfRxQp(Ptr<RdmaRxQueuePair> q){
	auto &v = m_rtTable[q->dip];
	if (v.size() > 0){
		return v[q->GetHash() % v.size()];
	}else{
		NS_ASSERT_MSG(false, "We assume at least one NIC is alive");
	}
}
void RdmaHw::DeleteRxQp(uint32_t dip, uint16_t pg, uint16_t dport){
	uint64_t key = ((uint64_t)dip << 32) | ((uint64_t)pg << 16) | (uint64_t)dport;
	m_rxQpMap.erase(key);
}

int RdmaHw::ReceiveUdp(Ptr<Packet> p, CustomHeader &ch){
	uint8_t ecnbits = ch.GetIpv4EcnBits();

	uint32_t payload_size = p->GetSize() - ch.GetSerializedSize();	//packet总大小减去报头大小，就是这个包里数据的大小

	// TODO find corresponding rx queue pair
	Ptr<RdmaRxQueuePair> rxQp = GetRxQp(ch.dip, ch.sip, ch.udp.dport, ch.udp.sport, ch.udp.pg, true);
	if (ecnbits != 0){
		rxQp->m_ecn_source.ecnbits |= ecnbits;
		rxQp->m_ecn_source.qfb++;
	}
	rxQp->m_ecn_source.total++;
	rxQp->m_milestone_rx = m_ack_interval;

	int x = ReceiverCheckSeq(ch.udp.seq, rxQp, payload_size);	//验证seq序列号
	//收到数据包后，返回Ack应答包
	if (x == 1 || x == 2){ //generate ACK or NACK
		qbbHeader seqh;
		seqh.SetSeq(rxQp->ReceiverNextExpectedSeq);
		seqh.SetPG(ch.udp.pg);
		seqh.SetSport(ch.udp.dport);		//应答包的源地址和目的地址与收到的packet相反
		seqh.SetDport(ch.udp.sport);
		seqh.SetIntHeader(ch.udp.ih);
		if (ecnbits)
			seqh.SetCnp();

		Ptr<Packet> newp = Create<Packet>(std::max(60-14-20-(int)seqh.GetSerializedSize(), 0));
		newp->AddHeader(seqh);

		Ipv4Header head;	// Prepare IPv4 header
		head.SetDestination(Ipv4Address(ch.sip));
		head.SetSource(Ipv4Address(ch.dip));
		head.SetProtocol(x == 1 ? 0xFC : 0xFD); //ack=0xFC nack=0xFD
		head.SetTtl(64);
		head.SetPayloadSize(newp->GetSize());
		head.SetIdentification(rxQp->m_ipid++);

		newp->AddHeader(head);
		AddHeader(newp, 0x800);	// Attach PPP header
		// send
		uint32_t nic_idx = GetNicIdxOfRxQp(rxQp);
		m_nic[nic_idx].dev->RdmaEnqueueHighPrioQ(newp);	//在相应网卡的端口的 最高优先级队列————RdmaEgressQueue类的m_ackQ队列中入队（ack queue）
		m_nic[nic_idx].dev->TriggerTransmit();			//在相应的网卡调用发送函数：QbbNetDevice::DequeueAndTransmit(void)
	}
	return 0;
}

//==========================发送端处理接收端发来的的CNP标记===============================
int RdmaHw::ReceiveCnp(Ptr<Packet> p, CustomHeader &ch){
	// QCN on NIC
	// This is a Congestion signal
	// Then, extract data from the congestion packet.
	// We assume, without verify, the packet is destinated to me
	uint32_t qIndex = ch.cnp.qIndex;
	if (qIndex == 1){		//DCTCP
		std::cout << "TCP--ignore\n";
		return 0;
	}
	uint16_t udpport = ch.cnp.fid; // corresponds to the sport
	uint8_t ecnbits = ch.cnp.ecnBits;
	uint16_t qfb = ch.cnp.qfb;
	uint16_t total = ch.cnp.total;

	uint32_t i;
	// get qp
	Ptr<RdmaQueuePair> qp = GetQp(ch.sip, udpport, qIndex);
	if (qp == NULL)
		std::cout << "ERROR: QCN NIC cannot find the flow\n";
	// get nic
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;

	if (qp->m_rate == 0)			//lazy initialization	
	{
		qp->m_rate = dev->GetDataRate();
		if (m_cc_mode == 1){
			qp->mlx.m_targetRate = dev->GetDataRate();
		}else if (m_cc_mode == 3){
			qp->hp.m_curRate = dev->GetDataRate();
			if (m_multipleRate){
				for (uint32_t i = 0; i < IntHeader::maxHop; i++)
					qp->hp.hopState[i].Rc = dev->GetDataRate();
			}
		}else if (m_cc_mode == 7){
			qp->tmly.m_curRate = dev->GetDataRate();
		}else if (m_cc_mode == 10){
			qp->hpccPint.m_curRate = dev->GetDataRate();
		}
	}
	return 0;
}
//==========================发送端处理接收端返回的Ack===============================
int RdmaHw::ReceiveAck(Ptr<Packet> p, CustomHeader &ch){
	uint16_t qIndex = ch.ack.pg;
	uint16_t port = ch.ack.dport;
	uint32_t seq = ch.ack.seq;
	uint8_t cnp = (ch.ack.flags >> qbbHeader::FLAG_CNP) & 1;
	int i;
	Ptr<RdmaQueuePair> qp = GetQp(ch.sip, port, qIndex);
	if (qp == NULL){
		std::cout << "ERROR: " << "node:" << m_node->GetId() << ' ' << (ch.l3Prot == 0xFC ? "ACK" : "NACK") << " NIC cannot find the flow\n";
		return 0;
	}

	uint32_t nic_idx = GetNicIdxOfQp(qp);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;
	if (m_ack_interval == 0)
		std::cout << "ERROR: shouldn't receive ack\n";
	else {
		if (!m_backto0){
			qp->Acknowledge(seq);
		}else {
			uint32_t goback_seq = seq / m_chunk * m_chunk;
			qp->Acknowledge(goback_seq);
		}
		if (qp->IsFinished()){
			QpComplete(qp);
		}
	}
	if (ch.l3Prot == 0xFD) // NACK
		RecoverQueue(qp);

	
	if(m_cc_mode == 11){
		Gimbal_test();
	}
	// handle cnp
	if (cnp){
		if (m_cc_mode == 1){ // mlx version
			cnp_received_mlx(qp);
		} 
	}

	if (m_cc_mode == 3){
		HandleAckHp(qp, p, ch);
		std::cout<<"HPCC  ";
	}else if (m_cc_mode == 7){
		HandleAckTimely(qp, p, ch);
	}else if (m_cc_mode == 8){
		HandleAckDctcp(qp, p, ch);
	}else if (m_cc_mode == 10){
		HandleAckHpPint(qp, p, ch);
	}
	// ACK may advance the on-the-fly window, allowing more packets to send
	dev->TriggerTransmit();
	return 0;
}
//用作dev->m_rdmaReceiveCb的回调函数
int RdmaHw::Receive(Ptr<Packet> p, CustomHeader &ch){
	if (ch.l3Prot == 0x11){ // UDP
		ReceiveUdp(p, ch);
	}else if (ch.l3Prot == 0xFF){ // CNP
		ReceiveCnp(p, ch);
	}else if (ch.l3Prot == 0xFD){ // NACK
		ReceiveAck(p, ch);
	}else if (ch.l3Prot == 0xFC){ // ACK
		ReceiveAck(p, ch);
	}
	return 0;
}

//验证seq序列号
int RdmaHw::ReceiverCheckSeq(uint32_t seq, Ptr<RdmaRxQueuePair> q, uint32_t size){
	uint32_t expected = q->ReceiverNextExpectedSeq;
	if (seq == expected){
		q->ReceiverNextExpectedSeq = expected + size;
		if (q->ReceiverNextExpectedSeq >= q->m_milestone_rx){
			q->m_milestone_rx += m_ack_interval;
			return 1; //Generate ACK
		}else if (q->ReceiverNextExpectedSeq % m_chunk == 0){
			return 1;
		}else {
			return 5;
		}
	} else if (seq > expected) {
		// Generate NACK
		if (Simulator::Now() >= q->m_nackTimer || q->m_lastNACK != expected){
			q->m_nackTimer = Simulator::Now() + MicroSeconds(m_nack_interval);
			q->m_lastNACK = expected;
			if (m_backto0){
				q->ReceiverNextExpectedSeq = q->ReceiverNextExpectedSeq / m_chunk*m_chunk;
			}
			return 2;
		}else
			return 4;
	}else {
		// Duplicate. 
		return 3;
	}
}
void RdmaHw::AddHeader (Ptr<Packet> p, uint16_t protocolNumber){
	PppHeader ppp;
	ppp.SetProtocol (EtherToPpp (protocolNumber));
	p->AddHeader (ppp);
}
uint16_t RdmaHw::EtherToPpp (uint16_t proto){
	switch(proto){
		case 0x0800: return 0x0021;   //IPv4
		case 0x86DD: return 0x0057;   //IPv6
		default: NS_ASSERT_MSG (false, "PPP Protocol number not defined!");
	}
	return 0;
}

void RdmaHw::RecoverQueue(Ptr<RdmaQueuePair> qp){
	qp->snd_nxt = qp->snd_una;
}

void RdmaHw::QpComplete(Ptr<RdmaQueuePair> qp){
	NS_ASSERT(!m_qpCompleteCallback.IsNull());
	if (m_cc_mode == 1){
		Simulator::Cancel(qp->mlx.m_eventUpdateAlpha);
		Simulator::Cancel(qp->mlx.m_eventDecreaseRate);
		Simulator::Cancel(qp->mlx.m_rpTimer);
	}

	// This callback will log info
	// It may also delete the rxQp on the receiver
	m_qpCompleteCallback(qp);

	qp->m_notifyAppFinish();

	// delete the qp
	DeleteQueuePair(qp);
}

void RdmaHw::SetLinkDown(Ptr<QbbNetDevice> dev){
	printf("RdmaHw: node:%u a link down\n", m_node->GetId());
}

void RdmaHw::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void RdmaHw::ClearTable(){
	m_rtTable.clear();
}

void RdmaHw::RedistributeQp(){
	// clear old qpGrp
	for (uint32_t i = 0; i < m_nic.size(); i++){
		if (m_nic[i].dev == NULL)
			continue;
		m_nic[i].qpGrp->Clear();
	}

	// redistribute qp
	for (auto &it : m_qpMap){
		Ptr<RdmaQueuePair> qp = it.second;
		uint32_t nic_idx = GetNicIdxOfQp(qp);
		m_nic[nic_idx].qpGrp->AddQp(qp);
		// Notify Nic
		m_nic[nic_idx].dev->ReassignedQp(qp);
	}
}

//获取下个packet，
//用作dev->m_rdmaEQ->m_rdmaGetNxtPkt的回调函数
Ptr<Packet> RdmaHw::GetNxtPacket(Ptr<RdmaQueuePair> qp){
	uint32_t payload_size = qp->GetBytesLeft();		//payload_size是负载，负载的初始值赋值为当前flow尚未发送的数据量
	if (m_mtu < payload_size)						//mtu就是最大传输单元，是一个packet能发送的最大大小这个是对的
		payload_size = m_mtu;						//但是payload_size最大不超过mtu
	Ptr<Packet> p = Create<Packet> (payload_size);
	// add SeqTsHeader
	SeqTsHeader seqTs;
	seqTs.SetSeq (qp->snd_nxt);
	seqTs.SetPG (qp->m_pg);
	p->AddHeader (seqTs);
	// add udp header
	UdpHeader udpHeader;
	udpHeader.SetDestinationPort (qp->dport);
	udpHeader.SetSourcePort (qp->sport);
	p->AddHeader (udpHeader);
	// add ipv4 header
	Ipv4Header ipHeader;
	ipHeader.SetSource (qp->sip);
	ipHeader.SetDestination (qp->dip);
	ipHeader.SetProtocol (0x11);
	ipHeader.SetPayloadSize (p->GetSize());
	ipHeader.SetTtl (64);
	ipHeader.SetTos (0);
	ipHeader.SetIdentification (qp->m_ipid);
	p->AddHeader(ipHeader);
	// add ppp header
	PppHeader ppp;
	ppp.SetProtocol (0x0021); // EtherToPpp(0x800), see point-to-point-net-device.cc
	p->AddHeader (ppp);

	// update state
	qp->snd_nxt += payload_size;
	qp->m_ipid++;

	// return
	return p;
}

void RdmaHw::PktSent(Ptr<RdmaQueuePair> qp, Ptr<Packet> pkt, Time interframeGap){
	qp->lastPktSize = pkt->GetSize();
	UpdateNextAvail(qp, interframeGap, pkt->GetSize());
}

void RdmaHw::UpdateNextAvail(Ptr<RdmaQueuePair> qp, Time interframeGap, uint32_t pkt_size){
	Time sendingTime;
	if (m_rateBound)
		sendingTime = interframeGap + Seconds(qp->m_rate.CalculateTxTime(pkt_size));
	else
		sendingTime = interframeGap + Seconds(qp->m_max_rate.CalculateTxTime(pkt_size));
	qp->m_nextAvail = Simulator::Now() + sendingTime;
}

void RdmaHw::ChangeRate(Ptr<RdmaQueuePair> qp, DataRate new_rate){
	#if 1
	Time sendingTime = Seconds(qp->m_rate.CalculateTxTime(qp->lastPktSize));
	Time new_sendintTime = Seconds(new_rate.CalculateTxTime(qp->lastPktSize));
	qp->m_nextAvail = qp->m_nextAvail + new_sendintTime - sendingTime;
	// update nic's next avail event
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	m_nic[nic_idx].dev->UpdateNextAvail(qp->m_nextAvail);
	#endif

	// change to new rate
	qp->m_rate = new_rate;
}

/*===============================================================================================================================
 *
 * Gimbal
 *
 * ==============================================================================================================================*/
#define Gimbal_LOG 0		//输出日志

#define MAX(a,b) (a>b? a:b)
#define MIN(a,b) (a>b? b:a)

#define SPDK_NVMF_TMGR_WEIGHT_PARAM (10)
#define SPDK_NVMF_TMGR_WEIGHT_ONE (1<<SPDK_NVMF_TMGR_WEIGHT_PARAM)	//write cost的下限为1，即读写花费资源相同（在这里是1KB）
#define SPDK_NVMF_TMGR_WC_BASELINE (9*SPDK_NVMF_TMGR_WEIGHT_ONE)	//write_cost的上限
#define SPDK_NVMF_TMGR_WC_DESCFACTOR (SPDK_NVMF_TMGR_WEIGHT_ONE/2)
#define SPDK_NVMF_TMGR_CONG_PARAM (10)
#define Second_To_NanoSecond 1000000000ULL

void RdmaHw::Gimbal_test(){
	//std::cout<<"成功！";
}

enum rate_state {//spdk_nvmf_tmgr_rate_state

	//以下是dual token bucket令牌桶的状态
	RATE_SUBMITTABLE,				//令牌足够，允许发送
	RATE_DEFERRED,					//没有足够的令牌，请求推迟

	//以下是论文3.3Rate Control Engine介绍的4种拥塞状态
	RATE_OVERLOADED,				// 	1. overload过载状态
	RATE_CONGESTION,				//	2. congestion拥塞状态
	RATE_CONGESTION_AVOIDANCE,		//	4. congestion avoidance拥塞避免状态
	RATE_UNDER_UTILIZED,			//	3. under_utilized未充分利用状态（源码中又称作slowstart状态）

	//这个在gimbal源代码中仅被定义，但没有被使用
	SPDK_NVMF_TMGR_RATE_DRAINING,	

	OPC_READ,						//SSD读操作
	OPC_WRITE,						//SSD写操作			
};


//初始化延迟和延迟阈值
void RdmaHw::Gimbal_cong_init()//spdk_nvmf_tmgr_lat_cong_init
{
	m_tmgr.cong.Lat_ewma = 0;				//EWMA_Latency	当前延迟
										
	m_tmgr.cong.Thresh_max = 1500;			//Thresh_max	单位：us(按照论文4.2节设置)
	m_tmgr.cong.Thresh_min = 250;			//Thresh_min	单位：us
	m_tmgr.cong.Thresh_cur = m_tmgr.cong.Thresh_max;	//Tresh_cur		单位：us

	m_tmgr.cong.Thresh_residue = 0;
}


void RdmaHw::Gimbal_rate_init()	//spdk_nvmf_tmgr_rate_init
{
	//rate->last_refill_tsc = spdk_get_ticks();			//获取当前时间
	m_tmgr.rate.target_rate = (1000UL) * 1024 * 1024;		//U:Unsigned无符号数 L:Long长整数 ，target_rate初始值为1000MB
	m_tmgr.rate.read_tokens = m_tmgr.rate.write_tokens = m_tmgr.rate.max_bucket_size = 256*1024;//令牌桶容量：256KB

	m_tmgr.rate.cpl_rate = 0;
	m_tmgr.rate.cpl_bytes = 0;
	//rate->cpl_rate_ticks = spdk_get_ticks_hz() / 10000;

	//rate->last_stat_bytes = 0;
	//rate->total_processed_bytes = 0;				//处理的字节总数
}


void RdmaHw::Gimbal_init() //√
{
	//TAILQ_INIT(&tmgr->read_queued);
	//TAILQ_INIT(&tmgr->write_queued);
	//tmgr->in_submit = false;
	// tmgr->poller = NULL;

	// SPDK_NOTICELOG("System tick rate: %llu/usec\n", spdk_get_ticks_hz()/SPDK_SEC_TO_USEC);

	Gimbal_rate_init();
	Gimbal_cong_init();

	//tmgr->iosched_ops = noop_ioched_ops;
	//tmgr->iosched_ops = wdrr_ioched_ops;

	m_tmgr.write_cost = SPDK_NVMF_TMGR_WC_BASELINE;
	return;
}



#define SPDK_NVMF_TMGR_EWMA(ewma, raw, param) ((raw >> param) + (ewma) - (ewma >> param))	
#define SPDK_NVMF_TMGR_EWMA_PARAM 	  1			// Weight = 1/(2^SPDK_NVMF_TMGR_EWMA_PARAM)
#define SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM 4		// Weight = 1/(2^SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM)	
//根据测量的延迟信息，返回拥塞状态
int	RdmaHw::Gimbal_cong_update(uint32_t latency)	//spdk_nvmf_tmgr_cong_update
{	//使用EWMA迭代公式更新EWMA_Latency（和论文中写法稍有不同,这里照搬源码）
	m_tmgr.cong.Lat_ewma = SPDK_NVMF_TMGR_EWMA(m_tmgr.cong.Lat_ewma,latency, 1);

	// cong->total_io++;						
	// cong->total_bytes += iolen;				
	// cong->total_lat_ticks += latency_ticks;	


	//overload: EWMA_Latency > Thresh_max
	if (m_tmgr.cong.Lat_ewma > m_tmgr.cong.Thresh_max) {
		m_tmgr.cong.Thresh_cur = (m_tmgr.cong.Thresh_cur + m_tmgr.cong.Thresh_max) / 2;	//与论文中有差异，论文中的Algorithm 1是 m_tmgr.cong.lathresh_tick = Thresh_max
		m_tmgr.cong.Thresh_residue = 0;
		// cong->congestion_count++;						
		// cong->overloaded_count++;
		return RATE_OVERLOADED;

	//congestion: Thresh_max > EWMA_Latency > Tresh_cur
	} else if (m_tmgr.cong.Lat_ewma > m_tmgr.cong.Thresh_cur) {
		m_tmgr.cong.Thresh_cur = (m_tmgr.cong.Thresh_cur + m_tmgr.cong.Thresh_max) / 2;	
		m_tmgr.cong.Thresh_residue = 0;
		// cong->congestion_count++;
		return RATE_CONGESTION;
	
	//avoidance: Tresh_cur > EWMA_Latency > Thresh_min
	} else if (m_tmgr.cong.Lat_ewma > m_tmgr.cong.Thresh_min) {
		m_tmgr.cong.Thresh_residue += (m_tmgr.cong.Thresh_cur - m_tmgr.cong.Lat_ewma);			//与论文有差异
		m_tmgr.cong.Thresh_cur -= m_tmgr.cong.Thresh_residue >> SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM;	
		m_tmgr.cong.Thresh_residue = m_tmgr.cong.Thresh_residue & ((1 << SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM) - 1);	//逻辑位移

	//under utilized: Thresh_min > EWMA_Latency
	} else {
		m_tmgr.cong.Thresh_residue += (m_tmgr.cong.Thresh_cur - m_tmgr.cong.Lat_ewma);
		m_tmgr.cong.Thresh_cur -= m_tmgr.cong.Thresh_residue >> SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM;
		m_tmgr.cong.Thresh_residue = m_tmgr.cong.Thresh_residue & ((1 << SPDK_NVMF_TMGR_LATHRES_EWMA_PARAM) - 1);
		return RATE_UNDER_UTILIZED;
	}
	return RATE_CONGESTION_AVOIDANCE;
}



void RdmaHw::Gimbal_cong_submit()
{
	// int		status, ret;
	// struct spdk_nvmf_request *req, *tmp;
	// uint64_t now = spdk_get_ticks();				//获取cpu当前时钟节拍

	Gimbal_rate_bucket_refill();	//更新token令牌数量
	//tmgr->in_submit = true;							//标志位，执行submit请求函数时置为true，循环结束后，退出函数时置为false

	// we process deferred requests first 
	//先处理延迟的请求

	//遍历read_queued中的每个request
	// TAILQ_FOREACH_SAFE(req, &tmgr->read_queued, link, tmp) {		
	// 	if (spdk_nvmf_tmgr_rate_is_submittable(tmgr, req) == SPDK_NVMF_TMGR_RATE_SUBMITTABLE) {	//判断是否有足够的令牌给当前的io请求,如果有，可以提交请求
	// 		spdk_nvmf_tmgr_rate_submit(tmgr, req);					//根据请求的读写类型，发放相应的令牌
	// 		TAILQ_REMOVE(&tmgr->read_queued, req, link);			//请求从读队列（read_queued）出队（为啥只有读队列）,赋值给req
	// 		TAILQ_INSERT_TAIL(&req->qpair->outstanding, req, link);	//--------???并插入outstanding队列的尾部???-----------

	// 		tmgr->io_outstanding += req->length;					
	// 		tmgr->io_waiting--;
	// 		status = spdk_nvmf_ctrlr_process_io_cmd(req);			//如果请求执行状态成功完成		
	// 		if (status == SPDK_NVMF_REQUEST_EXEC_STATUS_COMPLETE) {
	// 			spdk_nvmf_request_complete(req);
	// 		}
	// 	} else {
	// 		break;
	// 	}
	// }

	// //如果读写队列不空，直接退出?
	// if (!TAILQ_EMPTY(&tmgr->read_queued) && !TAILQ_EMPTY(&tmgr->write_queued)) {	//如果读写队列皆不空 

	// 	tmgr->in_submit = false;
	// 	return;
	// }

	// // if no requests in the deffered queue, we dequeue using io scheduler
	// //如果延迟队列中没有请求，则使用IO调度器出队
	// while (1) {
	// 	//traffic manager io scheduler options 出队  scheduler context
	// 	//如果延迟队列中没有请求，则使用IO调度器出队
	// 	if ((req = tmgr->iosched_ops.dequeue(tmgr->sched_ctx)) == NULL) {
	// 		break;
	// 	}
	
	// 	ret = spdk_nvmf_tmgr_rate_is_submittable(tmgr, req);	//判断是否有足够的令牌给当前的io请求
	// 	if (ret == SPDK_NVMF_TMGR_RATE_DEFERRED) {				//如果令牌不够
	// 		TAILQ_INSERT_TAIL(&tmgr->read_queued, req, link);	//插入read_queued队列的队尾
	// 		break;
	// 	}

	// 	spdk_nvmf_tmgr_rate_submit(tmgr, req);					//发放令牌
	// 	tmgr->io_outstanding += req->length;					
	// 	tmgr->io_waiting--;
	// 	TAILQ_INSERT_TAIL(&req->qpair->outstanding, req, link);	//将这个request放入此request对应的qpair的outstanding队列
	// 	status = spdk_nvmf_ctrlr_process_io_cmd(req);
	// 	if (status == SPDK_NVMF_REQUEST_EXEC_STATUS_COMPLETE) {
	// 		spdk_nvmf_request_complete(req);
	// 	}
	// }
	
	// tmgr->in_submit = false;	//标志位，执行submit请求函数时置为true，循环结束后，退出函数时置为false
	return;
}




//							写入/读出请求的数据大小				时延
void RdmaHw::Gimbal_cong_complete(uint32_t payload_size,uint32_t latency)	//spdk_nvmf_tmgr_complete
{
	// struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;
	// struct spdk_nvme_cpl *rsp = &req->rsp->nvme_cpl;
	// struct spdk_nvmf_qpair *qpair;
	// struct spdk_nvmf_subsystem_poll_group *sgroup = NULL;
	// struct spdk_nvmf_tmgr *tmgr;
	// struct spdk_nvmf_tmgr_lat_cong *cong;
	

	// qpair = req->qpair;
	// assert(qpair->ctrlr);
	// sgroup = &qpair->group->sgroups[qpair->ctrlr->subsys->id];	//sgroup:subsystem poll group
	// tmgr = sgroup->tmgr;

	// tmgr->io_outstanding -= req->length;		//未完成的请求数量-1
	Gimbal_rate_complete(payload_size);			
	// tmgr->iosched_ops.release(req);						//io请求执行完毕，释放请求

	// if (rsp->status.sct == SPDK_NVME_SCT_GENERIC && rsp->status.sc == SPDK_NVME_SC_SUCCESS) {

		int res = Gimbal_cong_update(latency);		//判断拥塞状态
		//overload过载状态:	
		if (res == RATE_OVERLOADED) {			
			if (m_tmgr.rate.target_rate > m_tmgr.rate.cpl_rate) {			//1.立即将速率调整为低于completion_rate
				m_tmgr.rate.target_rate = m_tmgr.rate.cpl_rate;	
			}
			m_tmgr.rate.write_tokens = 0;							//2.丢弃存储桶中剩余的令牌，以避免突发的提交
			m_tmgr.rate.read_tokens = 0;
			m_tmgr.rate.target_rate -= payload_size;
		//congested拥塞状态：
		} else if (res == RATE_CONGESTION) {
			m_tmgr.rate.target_rate -= payload_size;					//线性减小目标速率
		//underutilized未充分利用状态
		} else if (res == RATE_CONGESTION_AVOIDANCE) {			//以更快的速率线性增加目标速率
			m_tmgr.rate.target_rate += 8*payload_size;
		//congestion avoidance拥塞避免状态
		} else {		
			m_tmgr.rate.target_rate += payload_size;					//线性增加目标速率
		}

		//让目标速率保持在50MB到4GB之间
		m_tmgr.rate.target_rate = MAX(m_tmgr.rate.target_rate, 52428800);		//50MB
		m_tmgr.rate.target_rate = MIN(m_tmgr.rate.target_rate, 4294967296L);	//4GB

	// 	//???respones->reserved 保留的
	// 	rsp->rsvd1 = (cmd->rsvd2 << 16) + spdk_min((1 << 16) - 1, tmgr->iosched_ops.get_credit(req));
	// // }

	// if (!tmgr->in_submit) {
	// 	spdk_nvmf_tmgr_submit(tmgr);
	// }
	// return;
}
/*
#define SPDK_NVMF_TMGR_WEIGHT_PARAM (10)
#define SPDK_NVMF_TMGR_WEIGHT_ONE (1<<SPDK_NVMF_TMGR_WEIGHT_PARAM)	//write cost的下限为1，即读写花费资源相同（在这里是1KB）
#define SPDK_NVMF_TMGR_WC_BASELINE (9*SPDK_NVMF_TMGR_WEIGHT_ONE)	//write_cost的上限
#define SPDK_NVMF_TMGR_WC_DESCFACTOR (SPDK_NVMF_TMGR_WEIGHT_ONE/2)
#define SPDK_NVMF_TMGR_CONG_PARAM (10)
#define Second_To_NanoSecond 1000000000ULL
*/
void RdmaHw::Gimbal_rate_bucket_refill()	//spdk_nvmf_tmgr_rate_bucket_refill
{
	uint32_t now = Simulator::Now().GetNanoSeconds();	

	uint32_t delta_time = now - m_tmgr.rate.last_refill_time;						//计算上一次分配令牌到现在的时间(单位：ns)
	m_tmgr.rate.token = m_tmgr.rate.target_rate * delta_time / Second_To_NanoSecond;	//产生的令牌数量 = 目标速率 * 时间

	if(m_tmgr.rate.token > m_tmgr.rate.max_bucket_size)
		m_tmgr.rate.token = m_tmgr.rate.max_bucket_size;
																					

	// //根据IO成本（write cost）将令牌分配给每个存储桶
	// m_tmgr.rate.read_tokens += token * m_tmgr.write_cost / (m_tmgr.write_cost + SPDK_NVMF_TMGR_WEIGHT_ONE);
	// m_tmgr.rate.write_tokens += token * SPDK_NVMF_TMGR_WEIGHT_ONE / (m_tmgr.write_cost + SPDK_NVMF_TMGR_WEIGHT_ONE);

	// //如果读令牌桶溢出，溢出到写令牌桶
	// if (m_tmgr.rate.read_tokens > m_tmgr.rate.max_bucket_size) {
	// 	m_tmgr.rate.write_tokens = MIN(m_tmgr.rate.write_tokens + m_tmgr.rate.read_tokens - m_tmgr.rate.max_bucket_size, m_tmgr.rate.max_bucket_size);
	// 	m_tmgr.rate.read_tokens = m_tmgr.rate.max_bucket_size;
	// }
	// //如果写令牌桶溢出，溢出到读令牌桶
	// if (m_tmgr.rate.write_tokens > m_tmgr.rate.max_bucket_size) {
	// 	m_tmgr.rate.read_tokens = MIN(m_tmgr.rate.read_tokens + m_tmgr.rate.write_tokens - m_tmgr.rate.max_bucket_size, m_tmgr.rate.max_bucket_size);
	// 	m_tmgr.rate.write_tokens = m_tmgr.rate.max_bucket_size;
	// }
	m_tmgr.rate.last_refill_time = now;
	return;
}


//Dual Token Bucket双令牌桶：判断是否有足够的令牌给当前的io请求,如果有，可以提交请求
int RdmaHw::Gimbal_rate_is_submittable(uint32_t payload_size) 	//spdk_nvmf_tmgr_rate_is_submittable
{
	//struct spdk_nvmf_tmgr_rate *rate = &tmgr->rate;
	//struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;

	// //是写请求并且write_tokens足够，
	// if (opc == OPC_WRITE && m_tmgr.rate.write_tokens >= payload_size) {
	// 	return RATE_SUBMITTABLE;
	// //是读请求并且read_tokens足够
	// } else if (opc != OPC_WRITE && m_tmgr.rate.read_tokens >= payload_size) {
	// 	return RATE_SUBMITTABLE;
	// } else {
	// //没有足够的令牌，请求推迟
	// 	return RATE_DEFERRED;
	// }
	if(m_tmgr.rate.token >= payload_size)
		return RATE_SUBMITTABLE;
	else
		return RATE_DEFERRED;
}


//发放相应的令牌
void RdmaHw::Gimbal_rate_submit(uint32_t payload_size) //spdk_nvmf_tmgr_rate_submit
{
	//struct spdk_nvmf_tmgr_rate *rate = &tmgr->rate;
	//struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;	

	// if (opc == OPC_WRITE) {
	// 	m_tmgr.rate.write_tokens -= payload_size;		
	// } else {
	// 	m_tmgr.rate.read_tokens -= payload_size;
	// }
	m_tmgr.rate.token -= payload_size;
	return;
}


//io请求执行完毕，统计数据
void RdmaHw::Gimbal_rate_complete(uint32_t payload_size) //spdk_nvmf_tmgr_rate_complete
{
	//struct spdk_nvmf_tmgr_rate *rate = &tmgr->rate;
	// uint64_t now;
	// rate->total_processed_bytes += iolen;		//累计处理的字节总数
	// rate->total_completes++;					//累计处理的i/o总数
	m_tmgr.rate.cpl_bytes += payload_size;					//累计completion_byte，用来测量completion_rate

	
	if (m_tmgr.rate.cpl_bytes > 16777216) {//每当cpl_bytes累计大于16MB,更新completion_rate

		uint32_t now = Simulator::Now().GetNanoSeconds();

		// completion_rate = completion_byte / 上次更新的时间间隔
		m_tmgr.rate.cpl_rate = m_tmgr.rate.cpl_bytes * Second_To_NanoSecond / (now - m_tmgr.rate.last_cpl_rate_update_time);
		m_tmgr.rate.last_cpl_rate_update_time = now; 
		m_tmgr.rate.cpl_bytes = 0;
	}
}


// //更新write_cost
// void RdmaHw::Gimbal_set_write_cost(uint64_t write_cost)
// {
// 	m_tmgr.write_cost = write_cost;							//更新write_cost
// 	if (m_tmgr.write_cost > SPDK_NVMF_TMGR_WC_BASELINE)		//write_cost不能超过上限
// 		m_tmgr.write_cost = SPDK_NVMF_TMGR_WC_BASELINE;
// 	else if (m_tmgr.write_cost <= SPDK_NVMF_TMGR_WEIGHT_ONE)//write_cost不能低于下限。最低为1，表示读写花费相同
// 		m_tmgr.write_cost = SPDK_NVMF_TMGR_WEIGHT_ONE;
// 	return;
// }


// //此函数建议放在Gimbal_cong_update中，刚刚更新Lat_ewma之后
// void RdmaHw::Gimbal_update_write_cost(struct Latency_congestion *cong)
// {
// 	// struct spdk_nvmf_tmgr *tmgr = arg;
// 	uint64_t rio, wio, wr_avg_lat;
// 	uint32_t now = Simulator::Now().GetNanoSeconds();

// 	//这里要加上判断读写请求个数的代码，因为没有读请求时，write_cost可以慢慢降低

// 	//rio = tmgr->read_cong.total_io - tmgr->read_cong.last_stat_io;		//rio: 现有的读请求数量
// 	//wio = tmgr->write_cong.total_io - tmgr->write_cong.last_stat_io;	//wio: 现有的写请求数量
// 	// if (wio) {	//如果还存在写请求，那么 平均写时延是											
// 	// 	wr_avg_lat = (tmgr->write_cong.total_io - tmgr->write_cong.last_stat_io) / wio;
// 	// } else {	//如果不存在写请求，那么平均写时延为0
// 	// 	wr_avg_lat = 0;
// 	// }

// 	//还存在读请求，并且平均写时延大于最小延迟阈值————或者虽然不存在读请求，但平均写时延大于最大延迟阈值，那么write cost增加
// 	if ((rio && (m_tmgr.write_cong.Thresh_min < m_tmgr.write_cong.Lat_ewma)) || m_tmgr.write_cong.Lat_ewma > m_tmgr.write_cong.Thresh_max) {
// 		Gimbal_set_write_cost((m_tmgr.write_cost+SPDK_NVMF_TMGR_WC_BASELINE)/2);
// 	} else {//如果平均写时延小于最小延迟阈值————或者不存在读请求，那么write cost可以线性减小
// 		Gimbal_set_write_cost(m_tmgr.write_cost - SPDK_NVMF_TMGR_WC_DESCFACTOR);
// 	}
		
// 	// tmgr->rate.last_stat_bytes = tmgr->rate.total_processed_bytes;
// 	// tmgr->rate.last_stat_cpls = tmgr->rate.total_completes;
// 	// tmgr->read_cong.last_stat_io = tmgr->read_cong.total_io;
// 	// tmgr->read_cong.last_stat_bytes = tmgr->read_cong.total_bytes;
// 	// tmgr->read_cong.last_stat_lat_ticks = tmgr->read_cong.total_lat_ticks;
// 	// tmgr->write_cong.last_stat_io = tmgr->write_cong.total_io;
// 	// tmgr->write_cong.last_stat_bytes = tmgr->write_cong.total_bytes;
// 	// tmgr->write_cong.last_stat_lat_ticks = tmgr->write_cong.total_lat_ticks;
// 	// tmgr->stat_last_tsc = now;

// }














#define PRINT_LOG 0
/******************************
 * Mellanox's version of DCQCN
 *****************************/

//---------------------------更新α--------------------------------------------
void RdmaHw::UpdateAlphaMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	//std::cout << Simulator::Now() << " alpha update:" << m_node->GetId() << ' ' << q->mlx.m_alpha << ' ' << (int)q->mlx.m_alpha_cnp_arrived << '\n';
	//printf("%lu alpha update: %08x %08x %u %u %.6lf->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_alpha);
	#endif
	if (q->mlx.m_alpha_cnp_arrived){
		q->mlx.m_alpha = (1 - m_g)*q->mlx.m_alpha + m_g; 	//时间K内收到了CNP
	}else {
		q->mlx.m_alpha = (1 - m_g)*q->mlx.m_alpha; 			//时间K内没有收到CNP
	}
	#if PRINT_LOG
	//printf("%.6lf\n", q->mlx.m_alpha);
	#endif
	q->mlx.m_alpha_cnp_arrived = false; 					//将收到CNP的标志位还原
	ScheduleUpdateAlphaMlx(q);
}
void RdmaHw::ScheduleUpdateAlphaMlx(Ptr<RdmaQueuePair> q){
	//												更新α的时间间隔，默认是55us				更新α的函数
	q->mlx.m_eventUpdateAlpha = Simulator::Schedule(MicroSeconds(m_alpha_resume_interval), &RdmaHw::UpdateAlphaMlx, this, q);
}

//-----------------------------收到CNP标志位：更新α，更新速率---------------------------------------------
void RdmaHw::cnp_received_mlx(Ptr<RdmaQueuePair> q){
	//收到CNP时，将受到CNP的标志位置为true,一个用于更新α，一个用于更新发送速率，更新后重新置为false
	q->mlx.m_alpha_cnp_arrived = true; 		// set CNP_arrived bit for alpha update
	q->mlx.m_decrease_cnp_arrived = true; 	// set CNP_arrived bit for rate decrease
	//如果是发送端第一次收到CNP标记
	if (q->mlx.m_first_cnp){
		// init alpha
		q->mlx.m_alpha = 1;
		q->mlx.m_alpha_cnp_arrived = false;
		// schedule alpha update
		ScheduleUpdateAlphaMlx(q);
		// schedule rate decrease
		ScheduleDecreaseRateMlx(q, 1); 		//延迟1ns，以保证降低速率的事件发生在更新α之后
		// set rate on first CNP
		q->mlx.m_targetRate = q->m_rate = m_rateOnFirstCNP * q->m_rate;
		q->mlx.m_first_cnp = false;			//表示已经接受过首个CNP
	}
}

//---------------------------------------------------降低速率-----------------------------------------------------------
void RdmaHw::CheckRateDecreaseMlx(Ptr<RdmaQueuePair> q){
	ScheduleDecreaseRateMlx(q, 0);				//注册下一次的CheckRateDecreaseMlx 
	if (q->mlx.m_decrease_cnp_arrived){			//如果有收到CNP
		#if PRINT_LOG
		printf("%lu rate dec: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
		#endif

		//将当前速率设置为目标速率
		bool clamp = true;
		if (!m_EcnClampTgtRate){
			if (q->mlx.m_rpTimeStage == 0)
				clamp = false;
		}
		if (clamp)
			q->mlx.m_targetRate = q->m_rate;

		//更新（降低）当前速率RC
		q->m_rate = std::max(m_minRate, q->m_rate * (1 - q->mlx.m_alpha / 2));

		//重置速率增加的相关事宜
		q->mlx.m_rpTimeStage = 0;					//时间计数器Timer归零
		q->mlx.m_decrease_cnp_arrived = false;
		Simulator::Cancel(q->mlx.m_rpTimer);		//取消已经注册的m_rpTimer事件
		q->mlx.m_rpTimer = Simulator::Schedule(MicroSeconds(m_rpgTimeReset), &RdmaHw::RateIncEventTimerMlx, this, q);
		#if PRINT_LOG
		printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
		#endif
	}
}
void RdmaHw::ScheduleDecreaseRateMlx(Ptr<RdmaQueuePair> q, uint32_t delta){
	q->mlx.m_eventDecreaseRate = Simulator::Schedule(MicroSeconds(m_rateDecreaseInterval) + NanoSeconds(delta), &RdmaHw::CheckRateDecreaseMlx, this, q);
}

//---------------------------------------------------增加速率-----------------------------------------------------------
void RdmaHw::RateIncEventTimerMlx(Ptr<RdmaQueuePair> q){
	q->mlx.m_rpTimer = Simulator::Schedule(MicroSeconds(m_rpgTimeReset), &RdmaHw::RateIncEventTimerMlx, this, q);
	RateIncEventMlx(q);
	q->mlx.m_rpTimeStage++;		//时间计数+1
}

//根据计时器Timer，选择合适的速率增长阶段
void RdmaHw::RateIncEventMlx(Ptr<RdmaQueuePair> q){
	// check which increase phase: fast recovery, active increase, hyper increase
	//m_rpgThreshold:默认值为5，当时间计数小于5时，快速恢复，等于5时加性增长
	if (q->mlx.m_rpTimeStage < m_rpgThreshold){ 			// fast recovery 	快速恢复
		FastRecoveryMlx(q);
	}else if (q->mlx.m_rpTimeStage == m_rpgThreshold){ 		//active increase	加性增长
		ActiveIncreaseMlx(q);
	}else { 												// hyper increase	超级增长
		HyperIncreaseMlx(q);
	}
}

//快速恢复
void RdmaHw::FastRecoveryMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu fast recovery: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}
//加性增长
void RdmaHw::ActiveIncreaseMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu active inc: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	// get NIC
	uint32_t nic_idx = GetNicIdxOfQp(q);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;
	// increate rate
	q->mlx.m_targetRate += m_rai;
	if (q->mlx.m_targetRate > dev->GetDataRate())
		q->mlx.m_targetRate = dev->GetDataRate();
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}
//超级增长
void RdmaHw::HyperIncreaseMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu hyper inc: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	// get NIC
	uint32_t nic_idx = GetNicIdxOfQp(q);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;
	// increate rate
	q->mlx.m_targetRate += m_rhai;
	if (q->mlx.m_targetRate > dev->GetDataRate())
		q->mlx.m_targetRate = dev->GetDataRate();
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}



//=======================后面不用看================================================================================================================
//=======================后面不用看================================================================================================================
//=======================后面不用看================================================================================================================
//=======================后面不用看================================================================================================================
//=======================后面不用看================================================================================================================

/***********************
 * High Precision CC
 ***********************/
void RdmaHw::HandleAckHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	// update rate
	if (ack_seq > qp->hp.m_lastUpdateSeq){ // if full RTT feedback is ready, do full update
		UpdateRateHp(qp, p, ch, false);
	}else{ // do fast react
		FastReactHp(qp, p, ch);
	}
}

void RdmaHw::UpdateRateHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react){
	uint32_t next_seq = qp->snd_nxt;
	bool print = !fast_react || true;
	if (qp->hp.m_lastUpdateSeq == 0){ // first RTT
		qp->hp.m_lastUpdateSeq = next_seq;
		// store INT
		IntHeader &ih = ch.ack.ih;
		NS_ASSERT(ih.nhop <= IntHeader::maxHop);
		for (uint32_t i = 0; i < ih.nhop; i++)
			qp->hp.hop[i] = ih.hop[i];
		#if PRINT_LOG
		if (print){
			printf("%lu %s %08x %08x %u %u [%u,%u,%u]", Simulator::Now().GetTimeStep(), fast_react? "fast" : "update", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->hp.m_lastUpdateSeq, ch.ack.seq, next_seq);
			for (uint32_t i = 0; i < ih.nhop; i++)
				printf(" %u %lu %lu", ih.hop[i].GetQlen(), ih.hop[i].GetBytes(), ih.hop[i].GetTime());
			printf("\n");
		}
		#endif
	}else {
		// check packet INT
		IntHeader &ih = ch.ack.ih;
		if (ih.nhop <= IntHeader::maxHop){
			double max_c = 0;
			bool inStable = false;
			#if PRINT_LOG
			if (print)
				printf("%lu %s %08x %08x %u %u [%u,%u,%u]", Simulator::Now().GetTimeStep(), fast_react? "fast" : "update", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->hp.m_lastUpdateSeq, ch.ack.seq, next_seq);
			#endif
			// check each hop
			double U = 0;
			uint64_t dt = 0;
			bool updated[IntHeader::maxHop] = {false}, updated_any = false;
			NS_ASSERT(ih.nhop <= IntHeader::maxHop);
			for (uint32_t i = 0; i < ih.nhop; i++){
				if (m_sampleFeedback){
					if (ih.hop[i].GetQlen() == 0 && fast_react)
						continue;
				}
				updated[i] = updated_any = true;
				#if PRINT_LOG
				if (print)
					printf(" %u(%u) %lu(%lu) %lu(%lu)", ih.hop[i].GetQlen(), qp->hp.hop[i].GetQlen(), ih.hop[i].GetBytes(), qp->hp.hop[i].GetBytes(), ih.hop[i].GetTime(), qp->hp.hop[i].GetTime());
				#endif
				uint64_t tau = ih.hop[i].GetTimeDelta(qp->hp.hop[i]);;
				double duration = tau * 1e-9;
				double txRate = (ih.hop[i].GetBytesDelta(qp->hp.hop[i])) * 8 / duration;
				double u = txRate / ih.hop[i].GetLineRate() + (double)std::min(ih.hop[i].GetQlen(), qp->hp.hop[i].GetQlen()) * qp->m_max_rate.GetBitRate() / ih.hop[i].GetLineRate() /qp->m_win;
				#if PRINT_LOG
				if (print)
					printf(" %.3lf %.3lf", txRate, u);
				#endif
				if (!m_multipleRate){
					// for aggregate (single R)
					if (u > U){
						U = u;
						dt = tau;
					}
				}else {
					// for per hop (per hop R)
					if (tau > qp->m_baseRtt)
						tau = qp->m_baseRtt;
					qp->hp.hopState[i].u = (qp->hp.hopState[i].u * (qp->m_baseRtt - tau) + u * tau) / double(qp->m_baseRtt);
				}
				qp->hp.hop[i] = ih.hop[i];
			}

			DataRate new_rate;
			int32_t new_incStage;
			DataRate new_rate_per_hop[IntHeader::maxHop];
			int32_t new_incStage_per_hop[IntHeader::maxHop];
			if (!m_multipleRate){
				// for aggregate (single R)
				if (updated_any){
					if (dt > qp->m_baseRtt)
						dt = qp->m_baseRtt;
					qp->hp.u = (qp->hp.u * (qp->m_baseRtt - dt) + U * dt) / double(qp->m_baseRtt);
					max_c = qp->hp.u / m_targetUtil;

					if (max_c >= 1 || qp->hp.m_incStage >= m_miThresh){
						new_rate = qp->hp.m_curRate / max_c + m_rai;
						new_incStage = 0;
					}else{
						new_rate = qp->hp.m_curRate + m_rai;
						new_incStage = qp->hp.m_incStage+1;
					}
					if (new_rate < m_minRate)
						new_rate = m_minRate;
					if (new_rate > qp->m_max_rate)
						new_rate = qp->m_max_rate;
					#if PRINT_LOG
					if (print)
						printf(" u=%.6lf U=%.3lf dt=%u max_c=%.3lf", qp->hp.u, U, dt, max_c);
					#endif
					#if PRINT_LOG
					if (print)
						printf(" rate:%.3lf->%.3lf\n", qp->hp.m_curRate.GetBitRate()*1e-9, new_rate.GetBitRate()*1e-9);
					#endif
				}
			}else{
				// for per hop (per hop R)
				new_rate = qp->m_max_rate;
				for (uint32_t i = 0; i < ih.nhop; i++){
					if (updated[i]){
						double c = qp->hp.hopState[i].u / m_targetUtil;
						if (c >= 1 || qp->hp.hopState[i].incStage >= m_miThresh){
							new_rate_per_hop[i] = qp->hp.hopState[i].Rc / c + m_rai;
							new_incStage_per_hop[i] = 0;
						}else{
							new_rate_per_hop[i] = qp->hp.hopState[i].Rc + m_rai;
							new_incStage_per_hop[i] = qp->hp.hopState[i].incStage+1;
						}
						// bound rate
						if (new_rate_per_hop[i] < m_minRate)
							new_rate_per_hop[i] = m_minRate;
						if (new_rate_per_hop[i] > qp->m_max_rate)
							new_rate_per_hop[i] = qp->m_max_rate;
						// find min new_rate
						if (new_rate_per_hop[i] < new_rate)
							new_rate = new_rate_per_hop[i];
						#if PRINT_LOG
						if (print)
							printf(" [%u]u=%.6lf c=%.3lf", i, qp->hp.hopState[i].u, c);
						#endif
						#if PRINT_LOG
						if (print)
							printf(" %.3lf->%.3lf", qp->hp.hopState[i].Rc.GetBitRate()*1e-9, new_rate.GetBitRate()*1e-9);
						#endif
					}else{
						if (qp->hp.hopState[i].Rc < new_rate)
							new_rate = qp->hp.hopState[i].Rc;
					}
				}
				#if PRINT_LOG
				printf("\n");
				#endif
			}
			if (updated_any)
				ChangeRate(qp, new_rate);
			if (!fast_react){
				if (updated_any){
					qp->hp.m_curRate = new_rate;
					qp->hp.m_incStage = new_incStage;
				}
				if (m_multipleRate){
					// for per hop (per hop R)
					for (uint32_t i = 0; i < ih.nhop; i++){
						if (updated[i]){
							qp->hp.hopState[i].Rc = new_rate_per_hop[i];
							qp->hp.hopState[i].incStage = new_incStage_per_hop[i];
						}
					}
				}
			}
		}
		if (!fast_react){
			if (next_seq > qp->hp.m_lastUpdateSeq)
				qp->hp.m_lastUpdateSeq = next_seq; //+ rand() % 2 * m_mtu;
		}
	}
}

void RdmaHw::FastReactHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	if (m_fast_react)
		UpdateRateHp(qp, p, ch, true);
}

/**********************
 * TIMELY
 *********************/
void RdmaHw::HandleAckTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	// update rate
	if (ack_seq > qp->tmly.m_lastUpdateSeq){ // if full RTT feedback is ready, do full update
		UpdateRateTimely(qp, p, ch, false);
	}else{ // do fast react
		FastReactTimely(qp, p, ch);
	}
}
void RdmaHw::UpdateRateTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool us){
	uint32_t next_seq = qp->snd_nxt;
	uint64_t rtt = Simulator::Now().GetTimeStep() - ch.ack.ih.ts;
	bool print = !us;
	if (qp->tmly.m_lastUpdateSeq != 0){ // not first RTT
		int64_t new_rtt_diff = (int64_t)rtt - (int64_t)qp->tmly.lastRtt;
		double rtt_diff = (1 - m_tmly_alpha) * qp->tmly.rttDiff + m_tmly_alpha * new_rtt_diff;
		double gradient = rtt_diff / m_tmly_minRtt;
		bool inc = false;
		double c = 0;
		#if PRINT_LOG
		if (print)
			printf("%lu node:%u rtt:%lu rttDiff:%.0lf gradient:%.3lf rate:%.3lf", Simulator::Now().GetTimeStep(), m_node->GetId(), rtt, rtt_diff, gradient, qp->tmly.m_curRate.GetBitRate() * 1e-9);
		#endif
		if (rtt < m_tmly_TLow){
			inc = true;
		}else if (rtt > m_tmly_THigh){
			c = 1 - m_tmly_beta * (1 - (double)m_tmly_THigh / rtt);
			inc = false;
		}else if (gradient <= 0){
			inc = true;
		}else{
			c = 1 - m_tmly_beta * gradient;
			if (c < 0)
				c = 0;
			inc = false;
		}
		if (inc){
			if (qp->tmly.m_incStage < 5){
				qp->m_rate = qp->tmly.m_curRate + m_rai;
			}else{
				qp->m_rate = qp->tmly.m_curRate + m_rhai;
			}
			if (qp->m_rate > qp->m_max_rate)
				qp->m_rate = qp->m_max_rate;
			if (!us){
				qp->tmly.m_curRate = qp->m_rate;
				qp->tmly.m_incStage++;
				qp->tmly.rttDiff = rtt_diff;
			}
		}else{
			qp->m_rate = std::max(m_minRate, qp->tmly.m_curRate * c); 
			if (!us){
				qp->tmly.m_curRate = qp->m_rate;
				qp->tmly.m_incStage = 0;
				qp->tmly.rttDiff = rtt_diff;
			}
		}
		#if PRINT_LOG
		if (print){
			printf(" %c %.3lf\n", inc? '^':'v', qp->m_rate.GetBitRate() * 1e-9);
		}
		#endif
	}
	if (!us && next_seq > qp->tmly.m_lastUpdateSeq){
		qp->tmly.m_lastUpdateSeq = next_seq;
		// update
		qp->tmly.lastRtt = rtt;
	}
}
void RdmaHw::FastReactTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
}

/**********************
 * DCTCP
 *********************/
void RdmaHw::HandleAckDctcp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	uint8_t cnp = (ch.ack.flags >> qbbHeader::FLAG_CNP) & 1;
	bool new_batch = false;

	// update alpha
	qp->dctcp.m_ecnCnt += (cnp > 0);
	if (ack_seq > qp->dctcp.m_lastUpdateSeq){ // if full RTT feedback is ready, do alpha update
		#if PRINT_LOG
		printf("%lu %s %08x %08x %u %u [%u,%u,%u] %.3lf->", Simulator::Now().GetTimeStep(), "alpha", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->dctcp.m_lastUpdateSeq, ch.ack.seq, qp->snd_nxt, qp->dctcp.m_alpha);
		#endif
		new_batch = true;
		if (qp->dctcp.m_lastUpdateSeq == 0){ // first RTT
			qp->dctcp.m_lastUpdateSeq = qp->snd_nxt;
			qp->dctcp.m_batchSizeOfAlpha = qp->snd_nxt / m_mtu + 1;
		}else {
			double frac = std::min(1.0, double(qp->dctcp.m_ecnCnt) / qp->dctcp.m_batchSizeOfAlpha);
			qp->dctcp.m_alpha = (1 - m_g) * qp->dctcp.m_alpha + m_g * frac;
			qp->dctcp.m_lastUpdateSeq = qp->snd_nxt;
			qp->dctcp.m_ecnCnt = 0;
			qp->dctcp.m_batchSizeOfAlpha = (qp->snd_nxt - ack_seq) / m_mtu + 1;
			#if PRINT_LOG
			printf("%.3lf F:%.3lf", qp->dctcp.m_alpha, frac);
			#endif
		}
		#if PRINT_LOG
		printf("\n");
		#endif
	}

	// check cwr exit
	if (qp->dctcp.m_caState == 1){
		if (ack_seq > qp->dctcp.m_highSeq)
			qp->dctcp.m_caState = 0;
	}

	// check if need to reduce rate: ECN and not in CWR
	if (cnp && qp->dctcp.m_caState == 0){
		#if PRINT_LOG
		printf("%lu %s %08x %08x %u %u %.3lf->", Simulator::Now().GetTimeStep(), "rate", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->m_rate.GetBitRate()*1e-9);
		#endif
		qp->m_rate = std::max(m_minRate, qp->m_rate * (1 - qp->dctcp.m_alpha / 2));
		#if PRINT_LOG
		printf("%.3lf\n", qp->m_rate.GetBitRate() * 1e-9);
		#endif
		qp->dctcp.m_caState = 1;
		qp->dctcp.m_highSeq = qp->snd_nxt;
	}

	// additive inc
	if (qp->dctcp.m_caState == 0 && new_batch)
		qp->m_rate = std::min(qp->m_max_rate, qp->m_rate + m_dctcp_rai);
}

/*********************
 * HPCC-PINT
 ********************/
void RdmaHw::SetPintSmplThresh(double p){
       pint_smpl_thresh = (uint32_t)(65536 * p);
}
void RdmaHw::HandleAckHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
       uint32_t ack_seq = ch.ack.seq;
       if (rand() % 65536 >= pint_smpl_thresh)
               return;
       // update rate
       if (ack_seq > qp->hpccPint.m_lastUpdateSeq){ // if full RTT feedback is ready, do full update
               UpdateRateHpPint(qp, p, ch, false);
       }else{ // do fast react
               UpdateRateHpPint(qp, p, ch, true);
       }
}

void RdmaHw::UpdateRateHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react){
       uint32_t next_seq = qp->snd_nxt;
       if (qp->hpccPint.m_lastUpdateSeq == 0){ // first RTT
               qp->hpccPint.m_lastUpdateSeq = next_seq;
       }else {
               // check packet INT
               IntHeader &ih = ch.ack.ih;
               double U = Pint::decode_u(ih.GetPower());

               DataRate new_rate;
               int32_t new_incStage;
               double max_c = U / m_targetUtil;

               if (max_c >= 1 || qp->hpccPint.m_incStage >= m_miThresh){
                       new_rate = qp->hpccPint.m_curRate / max_c + m_rai;
                       new_incStage = 0;
               }else{
                       new_rate = qp->hpccPint.m_curRate + m_rai;
                       new_incStage = qp->hpccPint.m_incStage+1;
               }
               if (new_rate < m_minRate)
                       new_rate = m_minRate;
               if (new_rate > qp->m_max_rate)
                       new_rate = qp->m_max_rate;
               ChangeRate(qp, new_rate);
               if (!fast_react){
                       qp->hpccPint.m_curRate = new_rate;
                       qp->hpccPint.m_incStage = new_incStage;
               }
               if (!fast_react){
                       if (next_seq > qp->hpccPint.m_lastUpdateSeq)
                               qp->hpccPint.m_lastUpdateSeq = next_seq; //+ rand() % 2 * m_mtu;
               }
       }
}

}
