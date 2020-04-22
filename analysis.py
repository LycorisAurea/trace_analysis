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
        self.current_interval = None
        
        # counter parameter
        ## entropy item
        self.src_ip = Counter()
        self.dst_ip = Counter()
        self.sport = Counter()
        self.dport = Counter()
        self.packet_length = Counter()
        self.proto = Counter()
        ## count item
        self.packet_count = 0
        self.packet_length_count = 0

        # statistic serires
        ## collect entropy serires
        self.entropy_src_ip = []
        self.entropy_dst_ip = []
        self.entropy_sport = []
        self.entropy_dport = []
        self.entropy_packet_length = []
        self.entropy_proto = []
        ## collect count serires
        self.distinctItem_src_ip = []
        self.distinctItem_dst_ip = []
        self.distinctItem_sport = []
        self.distinctItem_dport = []
        self.distinctItem_packet_length = []
        self.distinctItem_proto = []
        self.total_packet_count = []
        self.total_packet_length = []
        self.average_packet_length = []

        # entropy calculation
        self.table = None
        
    def __cal_entropy_exact(self, container):
        total_items_cnt = 0
        entropy = 0
        for item, cnt in container.most_common():
            entropy += ( cnt * math.log(cnt) )
            total_items_cnt += cnt
        
        # whether container is empty, to avoid trace chasm
        if total_items_cnt == 0 or total_items_cnt == 1: return None

        # calculate entropy
        entropy -= ( total_items_cnt * math.log(total_items_cnt) )
        entropy = -entropy / total_items_cnt

        # normalized
        entropy /= math.log(total_items_cnt)

        return entropy
    
    def __cal_entropy_est_table(self, container):
        # k_value = 4, table_size=65536
        ## parameter
        k_value = 4
        k_register = [0,] * k_value
        total_item_cnt = 0
        entropy = 0
        
        ## function
        def hash_affine(in_data):
            para_a = [0xF28CF7CA, 0x8A00D025, 0x206FB589, 0xC0604F01]
            para_b = [0xAB57266E, 0xC7D7CD89, 0xDB89F988, 0xB12C2FF1]
            mersenne_p = 2**31-1

            hash_result = []
            for i in range(k_value):
                result = (para_a[i]*in_data + para_b[i])%mersenne_p
                hash_result.append(result%65536)
            return hash_result
        def str_to_int(in_data):
            if isinstance(in_data, str):
                # is ip
                int_ip = 0
                for i in range(4):
                    int_ip += (int(in_data.split('.')[i]) << ((3-i)*8))
                return int_ip       
            else: return in_data
        
        ## read results and calculate
        for item, cnt in container.most_common():
            # total cnt
            total_item_cnt += cnt

            # hash
            hash_result = hash_affine( str_to_int(item) )

            # query table
            try: query_result = [self.table[item] for item in hash_result]
            except TypeError:
                print('Error: No table.')
                exit(0)

            # store k value
            for i in range(k_value):
                k_register[i] += query_result[i] * cnt

        # est entropy
        if total_item_cnt ==0 or total_item_cnt == 1: return None
        else: 
            for i in range(k_value):
                k_register[i] /= total_item_cnt
                entropy += math.exp(k_register[i])
            entropy /= k_value
            entropy = -math.log(entropy)
            entropy /= math.log(total_item_cnt)
            return entropy

    def __cal_statistic_result(self, cal_entropy=None):
        # default cal method
        if cal_entropy == None: cal_entropy=self.__cal_entropy_exact
        
        # zero divide protection
        if self.packet_count == 0: average_packet_length = None
        else: average_packet_length = self.packet_length_count/self.packet_count

        # cal entropy result
        self.entropy_src_ip.append(cal_entropy(self.src_ip))
        self.entropy_dst_ip.append(cal_entropy(self.dst_ip))
        self.entropy_sport.append(cal_entropy(self.sport))
        self.entropy_dport.append(cal_entropy(self.dport))
        self.entropy_packet_length.append(cal_entropy(self.packet_length))
        self.entropy_proto.append(cal_entropy(self.proto))
        # cal count result
        self.distinctItem_src_ip.append( len(self.src_ip.values()) )
        self.distinctItem_dst_ip.append( len(self.dst_ip.values()) )
        self.distinctItem_sport.append( len(self.sport.values()) )
        self.distinctItem_dport.append( len(self.dport.values()) )
        self.distinctItem_packet_length.append( len(self.packet_length.values()) )
        self.distinctItem_proto.append( len(self.proto.values()) )
        self.total_packet_count.append(self.packet_count)
        self.total_packet_length.append(self.packet_length_count)
        self.average_packet_length.append(average_packet_length)

    def trace_analysis(self, file, time_interval, mode, entropy_cal_method='exact'):
        # mode = 'one_trace', 'first', 'mid', 'last'
        # entropy_cal_method = 'exact', 'est_table65536'

        # choice of est method
        if entropy_cal_method == 'exact': entropy_cal_function = self.__cal_entropy_exact
        elif entropy_cal_method == 'est_table65536': 
            entropy_cal_function = self.__cal_entropy_est_table

        # time parameter
        if mode == 'one_trace' or mode == 'first':
            self.current_interval = time_interval
        
        # get entropy
        with open(file, 'rb') as f:
            trace = dpkt.pcap.Reader(f)
            data_linktype = trace.datalink() # check raw packet or not
            for ts, buf in trace:        
                # get the first timestamp
                if mode == 'one_trace' or mode == 'first':
                    if self.first_time == None: self.first_time = ts
                
                # cal statistic result
                while ts > (self.first_time+self.current_interval):
                    self.__cal_statistic_result(entropy_cal_function)

                    # initial counter value
                    ## entropy item
                    self.src_ip.clear()
                    self.dst_ip.clear()
                    self.sport.clear()
                    self.dport.clear()
                    self.packet_length.clear()
                    self.proto.clear()
                    ## count item
                    self.packet_count = 0
                    self.packet_length_count = 0

                    # add current_interval
                    self.current_interval += time_interval
                
                # get items
                try: eth = dpkt.ethernet.Ethernet(buf)
                except AttributeError: pass
                except dpkt.dpkt.NeedData: pass
                
                ## packet count
                if data_linktype==1 and eth.type==dpkt.ethernet.ETH_TYPE_IP: # Ethernet
                    ip = eth.data
                    self.packet_count += 1
                    self.packet_length[ ip.len ] += 1
                    self.packet_length_count += ip.len
                elif data_linktype == 101: #Raw
                    ip = dpkt.ip.IP(buf)
                    self.packet_count += 1
                    self.packet_length[ ip.len ] += 1
                    self.packet_length_count += ip.len
                elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue
                else:
                    ip = eth.data
                    self.packet_count += 1
                    self.packet_length[ ip.len ] += 1
                    self.packet_length_count += ip.len

                self.src_ip[ socket.inet_ntop(socket.AF_INET, ip.src) ] += 1
                self.dst_ip[ socket.inet_ntop(socket.AF_INET, ip.dst) ] += 1
                self.proto[ ip.p ] += 1
                
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    try:
                        tcp = ip.data
                        self.sport[tcp.sport] += 1
                        self.dport[tcp.dport] += 1  
                    except AttributeError: pass
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    try:
                        udp = ip.data
                        self.sport[udp.sport] += 1
                        self.dport[udp.dport] += 1
                    except AttributeError: pass
            
        # end, put remaining data into list
        if mode == 'one_trace' or mode == 'last': self.__cal_statistic_result(entropy_cal_function)

    def import_table(self, table_path):
        self.table = []
        with open(table_path, 'r') as fin:
            lines = fin.readlines()
            for line in lines:
                self.table.append( int(line) )

    # get interface
    ## packet time
    def get_first_pkt_time(self):
        return self.first_time
    ## entropy item
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
    ## count item
    def get_distinctItem_src_ip(self):
        return self.distinctItem_src_ip
    def get_distinctItem_dst_ip(self):
        return self.distinctItem_dst_ip
    def get_distinctItem_sport(self):
        return self.distinctItem_sport
    def get_distinctItem_dport(self):
        return self.distinctItem_dport
    def get_distinctItem_pkt_len(self):
        return self.distinctItem_packet_length
    def get_distinctItem_proto(self):
        return self.distinctItem_proto
    def get_pkt_cnt(self):
        return self.total_packet_count
    def get_total_pkt_len_cnt(self):
        return self.total_packet_length
    def get_average_pkt_len_cnt(self):
        return self.average_packet_length
    ## initial this class
    def clear(self):
        # time parameter
        self.first_time = None
        self.current_interval = None
        
        # counter parameter
        ## entropy item
        self.src_ip.clear()
        self.dst_ip.clear()
        self.sport.clear()
        self.dport.clear()
        self.packet_length.clear()
        self.proto.clear()
        ## count item
        self.packet_count = 0
        self.packet_length_count = 0

        # collect entropy serires
        ## collect entropy serires
        self.entropy_src_ip = []
        self.entropy_dst_ip = []
        self.entropy_sport = []
        self.entropy_dport = []
        self.entropy_packet_length = []
        self.entropy_proto = []
        ## collect count serires
        self.distinctItem_src_ip = []
        self.distinctItem_dst_ip = []
        self.distinctItem_sport = []
        self.distinctItem_dport = []
        self.distinctItem_packet_length = []
        self.distinctItem_proto = []
        self.total_packet_count = []
        self.total_packet_length = []
        self.average_packet_length = []

class TracePlot(PacketAnalysis):
    def __init__(self, time_interval, mode='sec'):
        super(TracePlot, self).__init__()

        # pcap parameter
        self.time_interval = time_interval
        self.name_input_pcap = None
        self.dir_name = None
        self.output_location = ''

        # graph parameter
        self.mode = mode
        self.data = None
        self.attack_data = None
        self.color = dict(
            srcIP='#0000FF',     dstIP='#FF0000', 
            sport='#00CC96',     dport='#AB63FA', 
            pktLen='#FF8000',    proto='#CCCC00', 
            pktCnt='#000000',    totalPktLen='#BB3D00', 
            avrPktLen='#800080', markRegionOdd='#A0A0A0', 
            markRegionEven='#FFCCE5'
        )
    def __mkdir(self):
        os.system('mkdir {0}{1}'.format(self.output_location, self.dir_name))
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
            entropy_src_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_src_ip(), 
                    name='Source IP', marker={'color':self.color['srcIP']}), 
            entropy_dst_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_dst_ip(), 
                    name='Distination IP', marker={'color':self.color['dstIP']}),
            entropy_sport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_sport(), 
                    name='Source Ports', marker={'color':self.color['sport']}),
            entropy_dport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_dport(), 
                    name='Distination Ports', marker={'color':self.color['dport']}),
            entropy_pkt_len = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_pkt_len(), 
                    name='Packet Length', marker={'color':self.color['pktLen']}),
            entropy_proto = plotly.graph_objs.Scatter(x=time_axis, y=self.get_entropy_proto(), 
                    name='Protocol', marker={'color':self.color['proto']}), 
            
            distinct_src_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_src_ip(), 
                    name='Source IP', marker={'color':self.color['srcIP']}),
            distinct_dst_ip = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_dst_ip(), 
                    name='Distination IP', marker={'color':self.color['dstIP']}),
            distinct_sport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_sport(), 
                    name='Source Ports', marker={'color':self.color['sport']}),
            distinct_dport = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_dport(), 
                    name='Distination Ports', marker={'color':self.color['dport']}),
            distinct_pkt_len = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_pkt_len(), 
                    name='Packet Length', marker={'color':self.color['pktLen']}),
            distinct_proto = plotly.graph_objs.Scatter(x=time_axis, y=self.get_distinctItem_proto(), 
                    name='Protocol', marker={'color':self.color['proto']}), 
            count_pkt_cnt = plotly.graph_objs.Scatter(x=time_axis, y=self.get_pkt_cnt(), 
                    name='Packet Count', marker={'color':self.color['pktCnt']}),
            count_total_pkt_len = plotly.graph_objs.Scatter(x=time_axis, y=self.get_total_pkt_len_cnt(), 
                    name='Total Packet Length', marker={'color':self.color['totalPktLen']}, yaxis='y2'),
            count_average_pkt_len = plotly.graph_objs.Scatter(x=time_axis, y=self.get_average_pkt_len_cnt(), 
                    name='Average Packet Length', marker={'color':self.color['avrPktLen']}, yaxis='y2')
        )
        
        if self.__is_attack_list():
            data['one_entropy'] = plotly.graph_objs.Bar(
                x=self.attack_data['axis'], y=self.attack_data['region'], name='Attacks', 
                marker_color=self.attack_data['color'], opacity=0.6 , marker_line_width=0, xaxis='x2')
            
            data['sep'] = plotly.graph_objs.Bar(
                x=time_axis, y=self.attack_data['region'], name='Attacks', 
                marker_color=self.attack_data['color'], opacity=0.6, marker_line_width=0)
   
            data['one_count'] = plotly.graph_objs.Bar(
                x=self.attack_data['axis'], y=self.attack_data['region'], name='Attacks', 
                marker_color=self.attack_data['color'], opacity=0.6, marker_line_width=0, xaxis='x2', yaxis='y3')
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

    # analysis
    ## one trace file
    def one_analysis(self, input_pcap, entropy_cal_method='exact'):
        # pcap parameter
        try: self.name_input_pcap = input_pcap.split('/')[-1].split('.')[:-1][0]
        except IndexError: self.name_input_pcap = input_pcap.split('/')[-1]
        self.dir_name = 'Analysis_{0}_{1}s_{2}'.format(
            self.mode, self.time_interval, self.name_input_pcap)

        # mkdir
        self.__mkdir()

        # analysis trace
        self.trace_analysis(input_pcap, self.time_interval, 'one_trace', entropy_cal_method)  
        self.__data_update()
    
    ## several trace file
    def first_sep_analysis(self, input_pcap, entropy_cal_method='exact'):
        # pcap parameter
        try: self.name_input_pcap = input_pcap.split('/')[-1].split('.')[:-1][0]
        except IndexError: self.name_input_pcap = input_pcap.split('/')[-1]
        self.dir_name = 'Analysis_{0}_{1}s_{2}'.format(
            self.mode, self.time_interval, self.name_input_pcap)

        # mkdir
        self.__mkdir()

        # analysis trace
        self.trace_analysis(input_pcap, self.time_interval, 'first', entropy_cal_method)
    def mid_sep_analysis(self, input_pcap, entropy_cal_method='exact'):
        self.trace_analysis(input_pcap, self.time_interval, 'mid', entropy_cal_method)
    def last_sep_analysis(self, input_pcap, entropy_cal_method='exact'):
        self.trace_analysis(input_pcap, self.time_interval, 'last', entropy_cal_method)
        self.__data_update()

    # add attack list
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
        region_attacks = [str(i)+'n' for i in range(len(self.get_entropy_dst_ip()))]
        region_value = [0 for i in range(len(self.get_entropy_dst_ip()))]
        region_color = [self.color['markRegionOdd'], ]*len(self.get_entropy_dst_ip())
        cnt = 0
        for item in list_attacks:
            cnt += 1
            attack_name = item[0]
            isfrom = int(item[1])//self.time_interval
            isend = int(item[2])//self.time_interval
            mid = (isend-isfrom)//2 + isfrom
            region_attacks[mid] = attack_name+'({0})'.format(str(mid))
            if cnt%2:
                for num in range(isfrom-1, isend):
                    csv_mark[num] = attack_name
                    region_attacks[num] = attack_name+'({0})'.format(str(num))
                    region_value[num] = 1
            else:
                for num in range(isfrom-1, isend):
                    csv_mark[num] = attack_name
                    region_attacks[num] = attack_name+'({0})'.format(str(num))
                    region_value[num] = 1
                    region_color[num] = self.color['markRegionEven']
        self.attack_data =  dict(csv=csv_mark, axis=region_attacks, region=region_value, color=region_color)
        self.__data_update()
    
    # assign output location
    def import_output_location(self, location):
        if location[-1] == '/': self.output_location = location
        else: self.output_location = location + '/'

    # output plot, csv
    def entropy_one_plot(self, item):
        chart_file_name = '{0}{1}/Entropy_{2}_{3}s_{4}.html'.format(
            self.output_location, self.dir_name, self.mode, self.time_interval, self.name_input_pcap)
        
        list_data = [ self.data[i] for i in item ]
        if self.__is_attack_list():
            list_data.append(self.data['one_entropy'])

        
        if 'pkt_cnt' in item:
            layout_method = plotly.graph_objs.Layout(
                title='Entropy of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Entropy'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks'), 
                yaxis2=dict(overlaying='y', side='right', title='Packet Count'),
                bargap=0
            )
        else: 
            layout_method = plotly.graph_objs.Layout(
                title='Entropy of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Entropy'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks'),
                bargap=0
            )
        
        # plot
        plotly.offline.plot(
            {'data': list_data, 'layout': layout_method}, 
            filename=chart_file_name, 
            auto_open=False
        )
    def count_one_plot(self, item):
        chart_file_name = '{0}{1}/Distinct_{2}_{3}s_{4}.html'.format(
            self.output_location, self.dir_name, self.mode, self.time_interval, self.name_input_pcap)
        
        list_data = [ self.data[i] for i in item ]
        if self.__is_attack_list():
            list_data.append(self.data['one_count'])

        
        if 'count_total_pkt_len' or 'count_average_pkt_len' in item:
            layout_method = plotly.graph_objs.Layout(
                title='Distinct Items of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Count'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks'), 
                yaxis2=dict(overlaying='y', side='right', title='Bytes'),
                yaxis3=dict(overlaying='y', side='right'),
                bargap=0
            )
        else: 
            layout_method = plotly.graph_objs.Layout(
                title='Distinct Items of Trace: {0}'.format(self.name_input_pcap),
                xaxis=dict(title='Time'+' ({0})'.format(self.mode)), 
                yaxis=dict(title='Count'), 
                xaxis2=dict(overlaying='x', side='top', title='Attacks'),
                yaxis3=dict(overlaying='y', side='right'), 
                bargap=0
            )
        
        # plot
        plotly.offline.plot(
            {'data': list_data, 'layout': layout_method}, 
            filename=chart_file_name, 
            auto_open=False
        )
    def entropy_seperate_plot(self, item):
        num_chart = len(item)
        chart_file_name = '{0}{1}/sep_Entropy_{2}_{3}s_{4}.html'.format(
            self.output_location, self.dir_name, self.mode, self.time_interval, self.name_input_pcap)

        fig = plotly.subplots.make_subplots(
            rows=num_chart, cols=1, 
            specs=[ [{}] for i in range(num_chart) ],  
            subplot_titles=self.__item_fullname(item)
        )

        list_data = [ self.data[i] for i in item ]
        if self.__is_attack_list():
            fig.add_trace( self.data['sep'], row=1, col=1 )
        
        for i in range(num_chart):
            fig.add_trace( list_data[i], row=i+1, col=1 )
            if item[i] == 'pkt_cnt': fig.update_yaxes(title_text='Count', row=i+1, col=1)
            else: fig.update_yaxes(title_text='Entropy', range=[0,1], row=i+1, col=1)
        fig.update_xaxes(title='Time'+' ({0})'.format(self.mode), row=num_chart, col=1)
        
        # output
        fig.update_layout(title='Entropy of Trace: {0}'.format(self.name_input_pcap), bargap=0)
        #fig.show()
        plotly.offline.plot(fig, filename=chart_file_name, auto_open=False)
    def csv_output(self):
        title = ['time'+' ({0})'.format(self.mode), 
                    'Src IP Entropy', 'Src IP DistinctItem', 
                    'Dst IP Entropy', 'Dst IP DistinctItem', 
                    'Src Ports Entropy', 'Src Ports DistinctItem',
                    'Dst Ports Entropy', 'Dst Ports DistinctItem', 
                    'Protocol Entropy', 'Protocol DistinctItem', 
                    'Packet Length Entropy', 'Packet Length DistinctItem', 
                    'Total Packet Length', 'Average Packet Length', 
                    'Packet Count', 'Attack']
        time_axis = self.__time_axis()
        items = [time_axis, 
                self.get_entropy_src_ip(), self.get_distinctItem_src_ip(), 
                self.get_entropy_dst_ip(), self.get_distinctItem_dst_ip(), 
                self.get_entropy_sport(), self.get_distinctItem_sport(), 
                self.get_entropy_dport(), self.get_distinctItem_dport(), 
                self.get_entropy_proto(), self.get_distinctItem_proto(), 
                self.get_entropy_pkt_len(), self.get_distinctItem_pkt_len(), 
                self.get_total_pkt_len_cnt(), self.get_average_pkt_len_cnt(), 
                self.get_pkt_cnt()]
        if self.__is_attack_list(): items.append(self.attack_data['csv'])

        csv_items = list( zip(*items) )
        csv_output_file_name = '{0}{1}/Analysis_{2}_{3}s_{4}.csv'.format(self.output_location, 
            self.dir_name, self.mode, self.time_interval, self.name_input_pcap)
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
    myplot = TracePlot(time_interval, mode)
    myplot.one_analysis(input_pcap)
    if attack_list != 'none': myplot.import_attack_list(attack_list)
    myplot.entropy_one_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                                'entropy_pkt_len', 'entropy_proto'])
    myplot.entropy_seperate_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                            'entropy_pkt_len', 'entropy_proto'])
    myplot.count_one_plot(['count_pkt_cnt', 'count_total_pkt_len', 
                                'distinct_src_ip', 'distinct_dst_ip', 'distinct_sport', 'distinct_dport', 
                                'distinct_pkt_len', 'distinct_proto', 'count_average_pkt_len'])
    myplot.csv_output()

