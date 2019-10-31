import os 
import sys
import csv
import math
import dpkt
import plotly
import socket
import datetime
from collections import Counter

def cal_entropy(container):
    total_items_cnt = 0
    entropy = 0
    for item, cnt in container.most_common():
        entropy += ( cnt * math.log(cnt) )
        total_items_cnt += cnt
    entropy -= ( total_items_cnt * math.log(total_items_cnt) )
    entropy = -entropy / total_items_cnt

    # normalized
    entropy /= math.log(total_items_cnt)

    return entropy



# read parameter
try:
    input_pcap = sys.argv[1]
    time_interval = int(sys.argv[2])
except IndexError:
    print('Usage: python3 {0} <trace file> <time interval>'.format(sys.argv[0]))
    exit(0)
if os.path.isfile(input_pcap) == False:
    print('Error: Cannot find the file.')
    exit(0)
elif time_interval < 1:
    print('Error: time interval should >= 1 (sec)')
    exit(0)



# parameter
first_time = None
current_interval = time_interval

entropy_src_ip = []
entropy_dst_ip = []
entropy_sport = []
entropy_dport = []

src_ip = Counter()
dst_ip = Counter()
sport = Counter()
dport = Counter()

with open(input_pcap, 'rb') as f:
    trace = dpkt.pcap.Reader(f)
    
    for ts, buf in trace:         
        # get the first timestamp
        if first_time == None: first_time = ts
        
        # cal entropy result
        if ts > (first_time+current_interval):
            entropy_src_ip.append(cal_entropy(src_ip))
            entropy_dst_ip.append(cal_entropy(dst_ip))
            entropy_sport.append(cal_entropy(sport))
            entropy_dport.append(cal_entropy(dport))

            # clear
            src_ip.clear()
            dst_ip.clear()
            sport.clear()
            dport.clear()

            # add current_interval
            current_interval += time_interval

        
        # get items
        try: eth = dpkt.ethernet.Ethernet(buf)
        except AttributeError: pass
        except dpkt.dpkt.NeedData: pass
        
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: continue
        ip = eth.data

        src_ip[ socket.inet_ntop(socket.AF_INET, ip.src) ] += 1
        dst_ip[ socket.inet_ntop(socket.AF_INET, ip.dst) ] += 1
        
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            try:
                tcp = ip.data
                sport[tcp.sport] += 1
                dport[tcp.dport] += 1  
            except AttributeError: pass
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            try:
                udp = ip.data
                sport[udp.sport] += 1
                dport[udp.dport] += 1
            except AttributeError: pass
        
# last time
entropy_src_ip.append(cal_entropy(src_ip))
entropy_dst_ip.append(cal_entropy(dst_ip))
entropy_sport.append(cal_entropy(sport))
entropy_dport.append(cal_entropy(dport))        



# make a dir collect output data
dir_name = 'Analysis_{0}s_{1}'.format(time_interval, input_pcap.split('/')[-1].split('.')[:-1][0])
os.system('mkdir {0}'.format(dir_name))



# Create the graph
time_axis = [i+1 for i in range(len(entropy_dst_ip))]
date_time_axis = [
    datetime.datetime.fromtimestamp(first_time+i*time_interval).strftime("%H:%M:%S") for i in time_axis
]

chart_file_name = './{0}/Analysis_{1}s_{2}.html'.format(dir_name, time_interval, 
    input_pcap.split('/')[-1].split('.')[:-1][0])
plotly.offline.plot(
    {
        "data":
            [
            plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_src_ip, name='Source IP'), 
            plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dst_ip, name='Distination IP'),
            plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_sport, name='Source Ports'),
            plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dport, name='Distination Ports')
            ], 
        "layout":
            plotly.graph_objs.Layout(title='Entropy of Trace: {0}'.format(input_pcap.split('/')[-1]),
                xaxis=dict(title='Time'), yaxis=dict(title='Entropy', range=[0,1]))
    }, 
    filename=chart_file_name, 
    auto_open=False
)



# output csv
csv_title = ['time', 'Src IP', 'Dst IP', 'Src Ports', 'Dst Ports']
csv_time_axis = [ (i+1)*time_interval for i in range(len(entropy_src_ip)) ]
csv_items = [csv_time_axis, entropy_src_ip, entropy_dst_ip, entropy_sport, entropy_dport]
csv_items = list( zip(*csv_items) )

csv_output_file_name = './{0}/Analysis_{1}s_{2}.csv'.format(dir_name, time_interval, 
    input_pcap.split('/')[-1].split('.')[:-1][0])
with open(csv_output_file_name, 'w', encoding='utf-8') as fout:
    writer = csv.writer(fout, delimiter=',')
    
    writer.writerow(csv_title)
    for data in csv_items:
        writer.writerow(data)


