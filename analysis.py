import os 
import sys
import csv
import math
import dpkt
import plotly
import random
import socket
import datetime
from collections import Counter

class PacketAnalysis():
    def __init__(self, byteorder='big'):
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
        self.table = []
        self.k_value = None

        # data type
        self.byteorder = byteorder
        
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
        # parameter
        all_entropy = []
        result_entropy = 0
        
        # function
        def hash_affine(in_data, table_size):
            para_a = [
                0xF28CF7CA, 0x8A00D025, 0x206FB589, 0xC0604F01, 0xB21D60F4, 
                0x5B1E746, 0x1350A5F4, 0xA492C1E5, 0x4FF69EA, 0x3B0EE62, 
                0x42C2C69, 0x21E0C9D7, 0xA9894D6E, 0x29915818, 0xE244E6CA, 
                0x9D7EA43D, 0x67BD8005, 0xBC54FB46, 0x9697FF6E, 0xC6DE48F0
            ]
            para_b = [
                0xAB57266E, 0xC7D7CD89, 0xDB89F988, 0xB12C2FF1, 0xDA09D5B4, 
                0x82E653C0, 0x2F294A52, 0xBAF79C78, 0x2C661EEF, 0x99CCFC31, 
                0x6DB8DF96, 0xD30A3210, 0xA54D6CF9, 0x1F0C08EE, 0x7C46BEA2, 
                0x6A7E9CAD, 0x5FFEE981, 0xF0347F49, 0x64671BA2, 0xE91E4092
            ]
            mersenne_p = 2**31-1

            hash_result = []
            for i in range(self.k_value):
                result = (para_a[i]*in_data + para_b[i])%mersenne_p
                hash_result.append(result%table_size)
            return hash_result
        
        # get entropy of each table
        for table in self.table:
            ## parameter
            k_register = [0,] * self.k_value
            total_item_cnt = 0
            entropy = 0
            
            ## read results and calculate
            for item, cnt in container.most_common():
                # total cnt
                total_item_cnt += cnt

                # hash
                hash_result = hash_affine(item, len(table))

                # query table
                query_result = [table[key] for key in hash_result]

                # store k value
                for i in range(self.k_value):
                    k_register[i] += query_result[i] * cnt

            ## est entropy
            if total_item_cnt ==0 or total_item_cnt == 1: return None
            else: 
                for i in range(self.k_value):
                    k_register[i] /= total_item_cnt
                    entropy += math.exp(k_register[i])
                entropy /= self.k_value
                entropy = -math.log(entropy)
                entropy /= math.log(total_item_cnt)
                all_entropy.append(entropy)

        # calculate average entropy
        for item in all_entropy: result_entropy += item
        result_entropy /= len(all_entropy)
        return result_entropy
    
    def __cal_entropy_est_clifford(self, container):
        # parameter
        k_register = [0,] * self.k_value
        total_item_cnt = 0
        entropy = 0

        for item, cnt in container.most_common():
            # total cnt
            total_item_cnt += cnt

            # give item as seed
            random.seed(item)

            for i in range(self.k_value):
                # skewed stable distribution F(x; 1,−1, π/2, 0)
                u1 = random.uniform(0, 1)
                u2 = random.uniform(0, 1)
                """
                # unit 0.01
                u1 = int(u1*10000); u1 /= 10000
                if u1==0: u1=0.0001
                if u1==1: u1=0.9999
                u2 = int(u2*10000); u2 /= 10000
                if u2==0: u2=0.0001
                if u2==1: u2=0.9999
                """

                w1 = math.pi * (u1-0.5)
                w2 = -math.log(u2)

                ran1 = math.tan(w1) * (math.pi/2 - w1)
                ran2 = math.log( w2 * math.cos(w1) / (math.pi/2-w1) )
                ran = ran1 + ran2
                
                # store k value
                k_register[i] += ran * cnt
            
        # est entropy
        if total_item_cnt ==0 or total_item_cnt == 1: return None
        else: 
            for i in range(self.k_value):
                k_register[i] /= total_item_cnt
                entropy += math.exp(k_register[i])
            entropy /= self.k_value
            entropy = -math.log(entropy)
            entropy /= math.log(total_item_cnt)
            return entropy

    def __cal_entropy_est_table_square(self, container):
        # parameter
        all_entropy = []
        result_entropy = 0
        
        # function
        def lcg(in_data, table_size):
            para_a = 1103515245 # LCG gcc parameter
            para_b = 12345 # LCG gcc parameter
            mod_m = 2**31

            lcg_result = []
            result = in_data
            index_max = int( math.sqrt(table_size) )
            index_max_para = int( math.sqrt(table_size) )
            index_shift = 0
            while index_max_para != 1:
                index_max_para = index_max_para >> 1
                index_shift += 1

            for i in range(self.k_value):
                result = (para_a * result + para_b) % mod_m
                key_a = result >> (31-index_shift)
                
                result = (para_a * result + para_b) % mod_m
                key_b = result >> (31-index_shift)

                key_combine = key_a + key_b*index_max
                lcg_result.append(key_combine)
            return lcg_result
        
        # get entropy of each table
        for table in self.table:
            ## parameter
            k_register = [0,] * self.k_value
            total_item_cnt = 0
            entropy = 0
            
            ## read results and calculate
            for item, cnt in container.most_common():
                # total cnt
                total_item_cnt += cnt

                # hash
                hash_result = lcg(item, len(table))

                # query table
                query_result = [table[key] for key in hash_result]

                # store k value
                for i in range(self.k_value):
                    k_register[i] += query_result[i] * cnt

            ## est entropy
            if total_item_cnt ==0 or total_item_cnt == 1: return None
            else: 
                for i in range(self.k_value):
                    k_register[i] /= total_item_cnt
                    entropy += math.exp(k_register[i])
                entropy /= self.k_value
                entropy = -math.log(entropy)
                entropy /= math.log(total_item_cnt)
                all_entropy.append(entropy)

        # calculate average entropy
        for item in all_entropy: result_entropy += item
        result_entropy /= len(all_entropy)
        return result_entropy

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

    def trans_pcap_to_csv(self, file, output_file):
        with open(file, 'rb') as f:
            trace = dpkt.pcap.Reader(f)
            data_linktype = trace.datalink() # check raw packet or not

            # open csv file
            with open(output_file, 'w', encoding='utf-8') as fout:
                writer = csv.writer(fout, delimiter=',')
                writer.writerow(
                    ['Time', 'Source IP', 'Destination IP', 'Source Port', 
                    'Destination Port', 'IP Length', 'Protocol']
                )

                # read packet
                for ts, buf in trace:        
                    srcIP = ''
                    dstIP = ''
                    sport = ''
                    dport = ''
                    ipLen = ''
                    proto = ''
                    
                    # get items
                    try: eth = dpkt.ethernet.Ethernet(buf)
                    except AttributeError: pass
                    except dpkt.dpkt.NeedData: pass
                    
                    ## packet count
                    if data_linktype==1 and eth.type==dpkt.ethernet.ETH_TYPE_IP: # Ethernet
                        ip = eth.data
                        ipLen = ip.len
                    elif data_linktype == 101: #Raw
                        ip = dpkt.ip.IP(buf)
                        ipLen = ip.len
                    elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
                        continue
                    else:
                        ip = eth.data
                        ipLen = ip.len

                    srcIP = int.from_bytes(ip.src, byteorder=self.byteorder)
                    dstIP = int.from_bytes(ip.dst, byteorder=self.byteorder)
                    proto = ip.p
                    
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        try:
                            tcp = ip.data
                            sport = tcp.sport
                            dport = tcp.dport  
                        except AttributeError: pass
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        try:
                            udp = ip.data
                            sport = udp.sport
                            dport = udp.dport
                        except AttributeError: pass
                    
                    # output to csv file
                    writer.writerow([ts, srcIP, dstIP, sport, dport, ipLen, proto])
                
    def trace_analysis(self, file, time_interval, mode, entropy_cal_method='exact'):
        # mode = 'one_trace', 'first', 'mid', 'last'
        # entropy_cal_method = 'exact', 'est_clifford', 'est_tables', 'est_tables_square'

        # choice of est method
        if entropy_cal_method == 'exact': entropy_cal_function = self.__cal_entropy_exact
        elif entropy_cal_method == 'est_clifford': entropy_cal_function = self.__cal_entropy_est_clifford
        elif entropy_cal_method == 'est_tables': entropy_cal_function = self.__cal_entropy_est_table
        elif entropy_cal_method == 'est_tables_square': entropy_cal_function = self.__cal_entropy_est_table_square

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

                self.src_ip[ int.from_bytes(ip.src, byteorder=self.byteorder) ] += 1
                self.dst_ip[ int.from_bytes(ip.dst, byteorder=self.byteorder) ] += 1
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
    
    def trace_analysis_csv(self, file, time_interval, mode, entropy_cal_method='exact'):
        # mode = 'one_trace', 'first', 'mid', 'last'
        # entropy_cal_method = 'exact', 'est_clifford', 'est_tables', 'est_tables_square'

        # choice of est method
        if entropy_cal_method == 'exact': entropy_cal_function = self.__cal_entropy_exact
        elif entropy_cal_method == 'est_clifford': entropy_cal_function = self.__cal_entropy_est_clifford
        elif entropy_cal_method == 'est_tables': entropy_cal_function = self.__cal_entropy_est_table
        elif entropy_cal_method == 'est_tables_square': entropy_cal_function = self.__cal_entropy_est_table_square

        # time parameter
        if mode == 'one_trace' or mode == 'first':
            self.current_interval = time_interval
        
        # get entropy
        with open(file, 'r', newline='') as fin:
            # time=0, srcIP=1, dstIP=2, sport=3, dport=4, pktLen=5, proto=6         
            rows = csv.reader(fin)
            for element in rows:   
                # get element
                ## time  
                try: ts = float(element[0])
                except ValueError: continue
                
                ## ip
                if element[1] != '': srcIP = int(element[1])
                else: srcIP = None
                
                if element[2] != '': dstIP = int(element[2])
                else: dstIP = None
                
                ## port
                if element[3] != '': sport = int(element[3])
                else: sport = None
                
                if element[4] != '': dport = int(element[4])
                else: dport = None
                
                ## pktLen
                if element[5] != '': pktLen = int(element[5])
                else: pktLen = None
                
                ## proto
                if element[6] != '': proto = int(element[6])
                else: proto = None
                
                
                # get the first timestamp
                if mode == 'one_trace' or mode == 'first':
                    if self.first_time == None: self.first_time = ts
                
                # cal statistic result
                while ts > (self.first_time+self.current_interval):
                    # del None
                    del self.src_ip[None]
                    del self.dst_ip[None]
                    del self.sport[None]
                    del self.dport[None]
                    del self.packet_length[None]
                    del self.proto[None]

                    
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
                ## packet count
                self.packet_count += 1
                self.packet_length[ pktLen ] += 1
                self.packet_length_count += pktLen
                
                ## ip
                self.src_ip[ srcIP ] += 1
                self.dst_ip[ dstIP ] += 1
                self.proto[ proto ] += 1

                ## port
                self.sport[sport] += 1
                self.dport[dport] += 1
            
        # end, put remaining data into list
        if mode == 'one_trace' or mode == 'last': 
            # del None
            del self.src_ip[None]
            del self.dst_ip[None]
            del self.sport[None]
            del self.dport[None]
            del self.packet_length[None]
            del self.proto[None]
            self.__cal_statistic_result(entropy_cal_function)

    def import_table(self, table_path):
        for path in table_path:
            table = []
            with open(path, 'r') as fin:
                lines = fin.readlines()
                for line in lines:
                    try: table.append( float(line) )
                    except ValueError: continue
            self.table.append(table)

    def import_k_value(self, k_value):
        self.k_value = k_value

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

        # entropy calculation
        self.table = []

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
        if os.path.splitext(input_pcap)[1] == '.csv':
            self.trace_analysis_csv(input_pcap, self.time_interval, 'one_trace', entropy_cal_method) 
        else: 
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
                    if info[0] == '#': continue
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

