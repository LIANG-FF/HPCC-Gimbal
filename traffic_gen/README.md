# Traffic Generator 用于生成流量的脚本。

## Usage

`python traffic_gen.py -h` for help.
  -h, --help            显示帮助信息
  -c CDF_FILE           流量大小的累积分布函数                 
  -n NHOST,             hosts(结点的个数)                    
  -l LOAD               流量负载占网络容量(总带宽)的百分比，默认为0.3 
  -b BANDWIDTH          带宽————主机链路带宽，单位是(G/M/K)，默认为10G
  -t TIME               总运行时间，单位是(秒)，默认为10s
  -o OUTPUT             输出的流量文件的名称
                        

Example: 尝试生成一个流量文件：
`python traffic_gen.py -c WebSearch_distribution.txt -n 320 -l 0.3 -b 100G -t 0.1` generates traffic according to the web search flow size distribution, for 320 hosts, at 30% network load with 100Gbps host bandwidth for 0.1 seconds.

生成的流量可以直接用于simulation仿真

## Traffic format 流量文件（liang）的格式：

第一行:flow的数量
源主机 目的主机 3 目的主机的端口号 流量大小(单位:bytes) 发送的时间:(单位:秒)
Each line after that is a flow: `<source host> <dest host> 3 <dest port number> <flow size (bytes)> <start time (seconds)>`


## Flow size distributions
这里提供4个累积分布函数：
 `WebSearch_distribution.txt` 和 `FbHdp_distribution.txt` 是HPCC论文中用的 `AliStorage2019.txt` 收集自2019年阿里巴巴生产分布式存储系统
 `GoogleRPC2008.txt` 是谷歌在2008年之前的RPC大小分布。
