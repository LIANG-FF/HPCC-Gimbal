# HPCC NS-3 simulator
这是HPCC的NS3模拟器，
还包括了DCQCN, TIMELY, DCTCP, PFC, ECN and Broadcom shared buffer switch等功能的实现
[HPCC: High Precision Congestion Control (SIGCOMM' 2019)](https://rmiao.github.io/publications/hpcc-li.pdf). 

这个模拟器同样支持HPCC-PINT, HPCC-PINT将INT header开销减小到了只有1byte. 这就改善了长流(long flow)的完成时间. See [PINT: Probabilistic In-band Network Telemetry (SIGCOMM' 2020)](https://liyuliang001.github.io/publications/pint.pdf).

It is based on NS-3 version 3.17.

## Quick Start

### Build
`./waf configure`


### Experiment config 实验配置
Please see `mix/config.txt` for example. 

`mix/config_doc.txt` is a explanation of the example (texts in {..} are explanations).

`mix/fat.txt` 是HPCC和HPCC-PINT论文中的evaluation使用的拓扑

### Run
The direct command to run is:
`./waf --run 'scratch/third mix/config.txt'`

We provide a `run.py` for automatically *generating config* and *running experiment*. Please `pyt
hon run.py -h` for usage.

可选变量:
  -h, --help            显示帮助信息
  --cc CC               使用的拥塞控制算法：hp/dcqcn/timely/dctcp/hpccPint 
  --trace TRACE         流量文件
  --bw BW               网卡带宽
  --down DOWN           link down event
  --topo TOPO           拓扑文件
  --utgt UTGT           eta of HPCC
  --mi MI               MI_THRESH
  --hpai HPAI           AI for HPCC

  --pint_log_base PINT_LOG_BASE         PINT's log_base   (PINT不用管)
  --pint_prob PINT_PROB                 PINT's sampling probability
  --enable_tr ENABLE_TR                 enable packet-level events dump

Example usage:
`python run.py --cc hp --trace flow --bw 100 --topo topology --hpai 50`

To run HPCC-PINT, try:
`python run.py --cc hpccPint --trace flow --bw 100 --topo topology --hpai 50 --pint_log_base 1.05 --pint_prob 1`




## Files added/edited based on NS3 (不用看)
这里列出了一些编写源码所需的主要ns3文件。一些不重要或与核心逻辑无关的文件这里可能没有列出。

`point-to-point/model/qbb-net-device.cc/h`: the net-device RDMA

`point-to-point/model/pause-header.cc/h`: the header of PFC packet

`point-to-point/model/cn-header.cc/h`: the header of CNP

`point-to-point/model/pint.cc/h`: the PINT encoding/decoding algorithms

`point-to-point/model/qbb-header.cc/h`: the header of ACK

`point-to-point/model/qbb-channel.cc/h`: the channel of qbb-net-device

`point-to-point/model/qbb-remote-channel.cc/h`

`point-to-point/model/rdma-driver.cc/h`: layer of assigning qp and manage multiple NICs

`point-to-point/model/rdma-queue-pair.cc/h`: queue pair

`point-to-point/model/rdma-hw.cc/h`: the core logic of congestion control

`point-to-point/model/switch-node.cc/h`: the node class for switch

`point-to-point/model/switch-mmu.cc/h`: the mmu module of switch

`network/utils/broadcom-egress-queue.cc/h`: the multi-queue implementation of a switch port

`network/utils/custom-header.cc/h`: a customized header class for speeding up header parsing

`network/utils/int-header.cc/h`: the header of INT

`applications/model/rdma-client.cc/h`: the application of generating RDMA traffic

## Notes on other schemes (不用看)
DCQCN的实现是基于[Mellanox's implementation on CX4 and newer version](https://community.mellanox.com/s/article/dcqcn-parameters), 这个与DCQCN论文里的版本略有不同

TIMELY的实现是基于我们自己对TIMELY论文的理解.我们使用TIMELY论文中的参数. 论文中缺少的参数来自于 [this paper (footnote 4)](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/09/ecndelay-conext16.pdf).

The DCTCP implementation is a version that we envision DCTCP will be implemented in hardware. It starts at line rate (not slow start) which we believe is necessary in future high-speed network. It also does not delay ACK, because delayed ACk is for saving software overhead. These settings are consistent with other schemes.
DCTCP实现是我们设想的在硬件上实现DCTCP的版本。它以线性速率(line rate)启动，(而不是慢速启动(slow start))，我们认为这是未来的高速网络中必备的。它也不会延迟ACK，因为延迟ACK是为了节省软件开销。这些设置与其他方案一致。
