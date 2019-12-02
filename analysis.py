import os 
import sys
import csv
import math
import dpkt
import plotly
import socket
import datetime
from collections import Counter

class PacketAnalysis():
    def __init__(self):
        # time parameter
        self.first_time = None
        
        # collect entropy serires
        self.list_packet_count = []
        self.entropy_src_ip = []
        self.entropy_dst_ip = []
        self.entropy_sport = []
        self.entropy_dport = []
        self.entropy_packet_length = []
        self.entropy_proto = []
        
    def __cal_entropy_exact(self, container):
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

    def trace_analysis(self, file, time_interval):
        # time parameter
        current_interval = time_interval

        # counter parameter
        packet_count = 0
        src_ip = Counter()
        dst_ip = Counter()
        sport = Counter()
        dport = Counter()
        packet_length = Counter()
        proto = Counter()
        
        # get entropy
        with open(file, 'rb') as f:
            trace = dpkt.pcap.Reader(f)
            for ts, buf in trace:        
                # get the first timestamp
                if self.first_time == None: self.first_time = ts
                
                # cal entropy result
                if ts > (self.first_time+current_interval):
                    self.list_packet_count.append(packet_count)
                    self.entropy_src_ip.append(self.__cal_entropy_exact(src_ip))
                    self.entropy_dst_ip.append(self.__cal_entropy_exact(dst_ip))
                    self.entropy_sport.append(self.__cal_entropy_exact(sport))
                    self.entropy_dport.append(self.__cal_entropy_exact(dport))
                    self.entropy_packet_length.append(self.__cal_entropy_exact(packet_length))
                    self.entropy_proto.append(self.__cal_entropy_exact(proto))

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
            
        # end, put remaining data into list
        self.list_packet_count.append(packet_count)
        self.entropy_src_ip.append(self.__cal_entropy_exact(src_ip))
        self.entropy_dst_ip.append(self.__cal_entropy_exact(dst_ip))
        self.entropy_sport.append(self.__cal_entropy_exact(sport))
        self.entropy_dport.append(self.__cal_entropy_exact(dport))
        self.entropy_packet_length.append(self.__cal_entropy_exact(packet_length))
        self.entropy_proto.append(self.__cal_entropy_exact(proto))

    # get interface
    def get_first_pkt_time(self):
        return self.first_time
    def get_entropy_src_ip(self):
        return self.entropy_src_ip
    def get_entropy_dst_ip(self):
        return self.entropy_dst_ip
    def get_entropy_sport(self):
        return self.entropy_sport    
    def get_entropy_dport(self):
        return self.entropy_dport
    def get_entropy_pkt_len(self):
        return self.entropy_packet_length
    def get_entropy_proto(self):
        return self.entropy_proto    
    def get_pkt_cnt(self):
        return self.list_packet_count
    def clear(self):
        self.first_time = None
        self.list_packet_count = []
        self.entropy_src_ip = []
        self.entropy_dst_ip = []
        self.entropy_sport = []
        self.entropy_dport = []
        self.entropy_packet_length = []
        self.entropy_proto = []

class TracePlot(PacketAnalysis):
    def __init__(self, input_pcap, time_interval, mode='sec'):
        super(TracePlot, self).__init__()
        
        # pcap parameter
        self.time_interval = time_interval
        self.name_input_pcap = input_pcap.split('/')[-1].split('.')[:-1][0]
        self.dir_name = 'Analysis_{0}s_{1}'.format(self.time_interval, self.name_input_pcap)

        # graph parameter
        self.mode = mode
        self.data = None
        self.attack_data = None

        # mkdir
        self.__mkdir()

        # analysis trace
        self.trace_analysis(input_pcap, self.time_interval)  
        self.__data_update()
    def __mkdir(self):
        os.system('mkdir {0}'.format(self.dir_name))
    def __time_axis(self):
        time_axis = [i+1 for i in range(len(self.get_entropy_src_ip()))]
        if self.mode == 'real':
            date_time_axis = [
                datetime.datetime.fromtimestamp(self.first_time+i*self.time_interval)
                    .strftime("%H:%M:%S") for i in time_axis
            ]
        elif self.mode == 'sec':
            date_time_axis = [ i*self.time_interval for i in time_axis]
        
        elif self.mode == 'min':
            date_time_axis = [ i*self.time_interval//60 for i in time_axis]
        
        elif self.mode == 'hour':
            date_time_axis = [ i*self.time_interval//3600 for i in time_axis]
        
        return date_time_axis    
    def __data_generator(self):
        time_axis = self.__time_axis()
        data = dict(
            src_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_src_ip(), 
                    name='Source IP', marker={'color':'blue'}), 
            dst_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_dst_ip(), 
                    name='Distination IP', marker={'color':'red'}),
            sport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_sport(), 
                    name='Source Ports', marker={'color':'#00CC96'}),
            dport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_dport(), 
                    name='Distination Ports', marker={'color':'#AB63FA'}),
            pkt_cnt = plotly.graph_objs.Scatter(x=time_axis, y=self.get_pkt_cnt(), 
                    name='Packet Count', marker={'color':'orange'}, yaxis='y2'),
            pkt_len = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_pkt_len(), 
                    name='Packet Length', marker={'color':'pink'}),
            proto = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_proto(), 
                    name='Protocol', marker={'color':'#CCCC00'})
        )
        
        if self.__is_attack_list():
            data['odd_one'] = plotly.graph_objs.Scatter(
                x=self.attack_data['axis'], y=self.attack_data['odd'], name='Attacks', 
                fill='tozeroy', marker={'color':'#A0A0A0'}, xaxis='x2')
            data['even_one'] = plotly.graph_objs.Scatter(
                x=self.attack_data['axis'], y=self.attack_data['even'], name='Attacks', 
                fill='tozeroy', marker={'color':'#FFCCE5'}, xaxis='x2')
            
            data['odd_sep'] = plotly.graph_objs.Scatter(
                x=time_axis, y=self.attack_data['odd'], name='Attacks', 
                fill='tozeroy', marker={'color':'#A0A0A0'})
            data['even_sep'] = plotly.graph_objs.Scatter(
                x=time_axis, y=self.attack_data['even'], name='Attacks', 
                fill='tozeroy', marker={'color':'#FFCCE5'})
        
        return data
    def __data_update(self):
        self.data = self.__data_generator()
    def __is_attack_list(self):
        if self.attack_data == None: return False
        else: return True
    def __item_fullname(self, item):
        full_item = []
        for i in item:
            if i == 'src_ip': full_item.append('Source IP')
            elif i == 'dst_ip': full_item.append('Distination IP')
            elif i == 'sport': full_item.append('Source Port')
            elif i == 'dport': full_item.append('Distination Port')
            elif i == 'pkt_cnt': full_item.append('Packet Count')
            elif i == 'pkt_len': full_item.append('Paclet Length')
            elif i == 'proto': full_item.append('Protocol')
        return full_item


    def import_attack_list(self, file):     
        list_attacks = []
        with open(file, 'r') as fin:
            lines = fin.readlines()
            for line in lines:
                info = line.strip('\n')
                if info != '':
                    info = info.split(' ')
                    list_attacks.append(info)
                else: continue
        csv_mark = ['' for i in range(len(self.get_entropy_dst_ip()))]
        region_attacks = [str(i)+'m' for i in range(len(self.get_entropy_dst_ip()))]
        region_odd = [0 for i in range(len(self.get_entropy_dst_ip()))]
        region_even = [0 for i in range(len(self.get_entropy_dst_ip()))]
        cnt = 0
        for item in list_attacks:
            cnt += 1
            attack_name = item[0]
            isfrom = int(item[1])
            isend = int(item[2])
            mid = (isend-isfrom)//2 + isfrom
            region_attacks[mid] = attack_name+'({0})'.format(str(mid))
            if cnt%2:
                for num in range(isfrom, isend+1):
                    csv_mark[num] = attack_name
                    region_attacks[num] = attack_name+'({0})'.format(str(num))
                    region_odd[num] = 1
            else:
                for num in range(isfrom, isend+1):
                    csv_mark[num] = attack_name
                    region_attacks[num] = attack_name+'({0})'.format(str(num))
                    region_even[num] = 1
        self.attack_data =  dict(csv=csv_mark, axis=region_attacks, odd=region_odd, even=region_even)
        self.__data_update()
    def one_plot(self, item):
        chart_file_name = './{0}/one_Analysis_{1}s_{2}.html'.format(
            self.dir_name, self.time_interval, self.name_input_pcap)
        
        list_data = [ self.data[i] for i in item ]
        if self.__is_attack_list():
            list_data.append(self.data['odd_one'])
            list_data.append(self.data['even_one'])

        
        if 'pkt_cnt' in item:
            layout_method = plotly.graph_objs.Layout(
                title='Entropy of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Entropy'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks'), 
                yaxis2=dict(overlaying='y', side='right', title='Packet Count')
            )
        else: 
            layout_method = plotly.graph_objs.Layout(
                title='Entropy of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Entropy'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks')
            )
        
        # plot
        plotly.offline.plot(
            {'data': list_data, 'layout': layout_method}, 
            filename=chart_file_name, 
            auto_open=False
        )
    def seperate_plot(self, item):
        num_chart = len(item)
        chart_file_name = './{0}/sep_Analysis_{1}s_{2}.html'.format(
            self.dir_name, self.time_interval, self.name_input_pcap)

        fig = plotly.subplots.make_subplots(
            rows=num_chart, cols=1, 
            specs=[ [{}] for i in range(num_chart) ],  
            subplot_titles=self.__item_fullname(item)
        )

        list_data = [ self.data[i] for i in item ]
        if self.__is_attack_list():
            fig.add_trace( self.data['odd_sep'], row=1, col=1 )
            fig.add_trace( self.data['even_sep'], row=1, col=1 )
        
        for i in range(num_chart):
            fig.add_trace( list_data[i], row=i+1, col=1 )
            if item[i] == 'pkt_cnt': fig.update_yaxes(title_text='Count', row=i+1, col=1)
            else: fig.update_yaxes(title_text='Entropy', range=[0,1], row=i+1, col=1)
        fig.update_xaxes(title='Time'+' ({0})'.format(self.mode), row=num_chart, col=1)
        
        # output
        fig.update_layout(title='Entropy of Trace: {0}'.format(self.name_input_pcap))
        #fig.show()
        plotly.offline.plot(fig, filename=chart_file_name, auto_open=False)
    def csv_output(self):
        title = ['time'+' ({0})'.format(self.mode), 'Src IP', 'Dst IP', 'Src Ports', 'Dst Ports', 
                'Packet Count', 'Packet Length', 'Protocol', 'Attack']
        time_axis = self.__time_axis()
        items = [time_axis, self.get_entropy_src_ip(), self.get_entropy_dst_ip(), 
                self.get_entropy_sport(), self.get_entropy_dport(), 
                self.get_pkt_cnt(), self.get_entropy_pkt_len(), self.get_entropy_proto()]
        if self.__is_attack_list(): items.append(self.attack_data['csv'])

        csv_items = list( zip(*items) )
        csv_output_file_name = './{0}/Analysis_{1}s_{2}.csv'.format(self.dir_name, 
                self.time_interval, self.name_input_pcap)
        with open(csv_output_file_name, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            
            writer.writerow(title)
            for data in csv_items:
                writer.writerow(data)


if __name__ == '__main__':
    # read parameter
    try:
        input_pcap = sys.argv[1]
        attack_list = sys.argv[2]
        mode = sys.argv[3]
        time_interval = int(sys.argv[4])
    except IndexError:
        print(
            'Usage: python3 {0} <trace file>  <attack list(or \'none\')> <mode:sec/min/hour/real> <time interval(sec)>'.format(
            sys.argv[0]))
        exit(0)
    
    if os.path.isfile(input_pcap) == False:
        print('Error: Cannot find the file.')
        exit(0)
    elif time_interval < 1:
        print('Error: time interval should >= 1 (sec)')
        exit(0)
    elif mode != 'sec' and mode != 'min' and mode != 'hour' and mode != 'real':
        print('Error: mode must be \'real\', \'sec\', \'min\', \'hour\'.')
        exit(0)

    # analysis and plot
    myplot = TracePlot(input_pcap, time_interval, mode)
    if attack_list != 'none': myplot.import_attack_list(attack_list)
    myplot.one_plot(['src_ip', 'dst_ip', 'sport', 'dport', 'pkt_cnt', 'pkt_len', 'proto'])
    myplot.seperate_plot(['src_ip', 'dst_ip', 'sport', 'dport', 'pkt_cnt', 'pkt_len', 'proto'])
    myplot.csv_output()

