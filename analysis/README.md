# Analysis
此文件夹包括用于分析的代码和脚本。

## FCT(flow completion time) analysis
`fct_analysis.py` : 分析 fct，读取多个fct files (simulation的仿真输出), 并可以打印输出HPCC论文中的Figure 11 (a) 和 (c)

Usage: please check `python fct_analysis.py -h` and read line 20-26 in `fct_analysis.py`

usage: fct_analysis.py [-h] [-p PREFIX] [-s STEP] [-t TYPE] [-T TIME_LIMIT]
                       [-b BW]

可选变量:
  -h, --help     显示帮助信息
  -p PREFIX      Specify the prefix of the fct file. Usually like
                 fct_<topology>_<trace>
  -s STEP
  -t TYPE        0: normal, 1: incast, 2: all
  -T TIME_LIMIT  只考虑在时间T之前结束的流
  -b BW          bandwidth of edge link (Gbps)


## Trace reader
`trace_reader` 用来解析simulation模拟输出的.tr文件

### Usage: 
1. `make trace_reader`

2. `./trace_reader <.tr file> [filter_expr]`. [filter_expr]用于筛选事件
For example, `time > 2000010000` will display only events after 2000010000, `sip=0x0b000101&dip=0x0b000201` will display only events with sip=0x0b000101 and dip=0x0b000201.  (我们可能会在未来提出更详细的描述。现在，请阅读trace_filter.hpp了解更多细节).

### Output:
Each line is like:

  时间(ns)  结点  端口/队列  队列长度 入队  没有打上ECN标签   源地址(16进制)  目的地址   源端口  目的端口    序列号   发送时间戳  优先级  负载
`2000055540 n:338   4:3     100608  Enqu    ecn:0            0b00d101    0b012301   10000   100 U     161000    0           3     1048(1000)`

It means: at time 2000055540ns, at node 338, port 4, queue #3, the queue length is 100608B, and a packet is enqueued; the packet does not have ECN marked, is from 11.0.209.1:10000 to 11.1.35.1:100, is a data packet (U), sequence number 161000, tx timestamp 0, priority group 3, packet size 1048B, payload 1000B.
表示:时间为2000055540ns，节点338，端口4，队列#3，队列长度为100608B，有一个报文进入队列;报文没有ECN标记，从11.0.209.1:10000到11.1.35.1:100，是一个数据包(U)，序列号161000，发送时间戳0，优先级组3，报文大小1048B，载荷1000B。

There are other types of packets. Please refer to print_trace() in utils.hpp for details.
