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

packet_count = 0

list_packet_count = []
entropy_src_ip = []
entropy_dst_ip = []
entropy_sport = []
entropy_dport = []
entropy_packet_length = []
entropy_proto = []

src_ip = Counter()
dst_ip = Counter()
sport = Counter()
dport = Counter()
packet_length = Counter()
proto = Counter()

with open(input_pcap, 'rb') as f:
    trace = dpkt.pcap.Reader(f)
    
    for ts, buf in trace:        
        # get the first timestamp
        if first_time == None: first_time = ts
        
        # cal entropy result
        if ts > (first_time+current_interval):
            list_packet_count.append(packet_count)
            entropy_src_ip.append(cal_entropy(src_ip))
            entropy_dst_ip.append(cal_entropy(dst_ip))
            entropy_sport.append(cal_entropy(sport))
            entropy_dport.append(cal_entropy(dport))
            entropy_packet_length.append(cal_entropy(packet_length))
            entropy_proto.append(cal_entropy(proto))

            # clear
            packet_count = 0
            src_ip.clear()
            dst_ip.clear()
            sport.clear()
            dport.clear()
            packet_length.clear()
            proto.clear()

            # add current_interval
            current_interval += time_interval

        
        # get items
        try: eth = dpkt.ethernet.Ethernet(buf)
        except AttributeError: pass
        except dpkt.dpkt.NeedData: pass
        
        ## packet count
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: continue
        else: 
            packet_count += 1
            packet_length[ len(buf) ] += 1
        
        ip = eth.data
        src_ip[ socket.inet_ntop(socket.AF_INET, ip.src) ] += 1
        dst_ip[ socket.inet_ntop(socket.AF_INET, ip.dst) ] += 1
        proto[ ip.p ] += 1
        
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
list_packet_count.append(packet_count)
entropy_src_ip.append(cal_entropy(src_ip))
entropy_dst_ip.append(cal_entropy(dst_ip))
entropy_sport.append(cal_entropy(sport))
entropy_dport.append(cal_entropy(dport))
entropy_packet_length.append(cal_entropy(packet_length))        



# make a dir collect output data
dir_name = 'Analysis_{0}s_{1}'.format(time_interval, input_pcap.split('/')[-1].split('.')[:-1][0])
os.system('mkdir {0}'.format(dir_name))



# Create the graph
time_axis = [i+1 for i in range(len(entropy_dst_ip))]
#date_time_axis = [ i*time_interval//60 for i in time_axis]
date_time_axis = [
    datetime.datetime.fromtimestamp(first_time+i*time_interval).strftime("%H:%M:%S") for i in time_axis
]

chart_file_name = './{0}/Analysis_{1}s_{2}.html'.format(dir_name, time_interval, 
    input_pcap.split('/')[-1].split('.')[:-1][0])

fig = plotly.subplots.make_subplots(
    rows=5, cols=2, 
    specs=[
        [{'colspan': 2}, None], [{}, {}], [{}, {}], [{}, {}], [{}, {}]
    ], 
    subplot_titles=('Total', 'Source IP', 'Distination IP', 'Source Ports', 
        'Distination Ports', 'Packet Count', 'Packet Length', 'Protocol'),
)
# first chart
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_src_ip, 
        name='Source IP', marker={'color':'blue'}), row=1, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dst_ip, 
        name='Distination IP', marker={'color':'red'}), row=1, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_sport, 
        name='Source Ports', marker={'color':'#00CC96'}), row=1, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dport, 
        name='Distination Ports', marker={'color':'#AB63FA'}), row=1, col=1
)

# 2, 3, 4, 5 chart
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_src_ip, 
        name='Source IP', marker={'color':'blue'}), row=2, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dst_ip, 
        name='Distination IP', marker={'color':'red'}), row=2, col=2
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_sport, 
        name='Source Ports', marker={'color':'#00CC96'}), row=3, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_dport, 
        name='Distination Ports', marker={'color':'#AB63FA'}), row=3, col=2
)

# 6, 7, 8 chart
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=list_packet_count, 
        name='Packet Count', marker={'color':'orange'}), row=4, col=1
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_packet_length, 
        name='Packet Length', marker={'color':'pink'}), row=4, col=2
)
fig.add_trace(
    plotly.graph_objs.Scatter(x=date_time_axis, y=entropy_proto, 
        name='Protocol', marker={'color':'#CCCC00'}), row=5, col=1
)


# axis
fig.update_xaxes(title_text='Time', row=1, col=1)
fig.update_xaxes(title_text='Time', row=2, col=1)
fig.update_xaxes(title_text='Time', row=2, col=2)
fig.update_xaxes(title_text='Time', row=3, col=1)
fig.update_xaxes(title_text='Time', row=3, col=2)
fig.update_xaxes(title_text='Time', row=4, col=1)
fig.update_xaxes(title_text='Time', row=4, col=2)
fig.update_xaxes(title_text='Time', row=5, col=1)

fig.update_yaxes(title_text='Entropy', range=[0,1], row=1, col=1)
fig.update_yaxes(title_text='Entropy', row=2, col=1)
fig.update_yaxes(title_text='Entropy', row=2, col=2)
fig.update_yaxes(title_text='Entropy', row=3, col=1)
fig.update_yaxes(title_text='Entropy', row=3, col=2)
fig.update_yaxes(title_text='Number', row=4, col=1)
fig.update_yaxes(title_text='Entropy', row=4, col=2)
fig.update_yaxes(title_text='Entropy', row=5, col=1)

# output
fig.update_layout(title='Entropy of Trace: {0}'.format(input_pcap.split('/')[-1]))
#fig.show()
plotly.offline.plot(fig, filename=chart_file_name, auto_open=False)


"""
# one figure version
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
"""


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


