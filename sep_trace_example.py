import analysis

# pcap file path
file1 = 'example_1.pcap'
file2 = 'example_2.pcap'
file3 = 'example_3.pcap'
file4 = 'example_4.pcap'

# analysis parameter
mode = 'sec'
time_interval = 60
myplot = analysis.TracePlot(time_interval, mode)

# give pcap file
print('Now analysis pcap 1')
myplot.first_sep_analysis(file1)

print('Now analysis pcap 2')
myplot.mid_sep_analysis(file2)

print('Now analysis pcap 3')
myplot.mid_sep_analysis(file3)

print('Now analysis pcap 4')
myplot.last_sep_analysis(file4)

# give attack list
myplot.import_attack_list('attack_list_example.txt')

# plot picture
myplot.entropy_one_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                            'entropy_pkt_len', 'entropy_proto'])
myplot.entropy_seperate_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                                'entropy_pkt_len', 'entropy_proto'])
myplot.count_one_plot(['count_pkt_cnt', 'count_total_pkt_len', 
                        'distinct_src_ip', 'distinct_dst_ip', 'distinct_sport', 'distinct_dport', 
                            'distinct_pkt_len', 'distinct_proto', 'count_average_pkt_len'])
myplot.csv_output()





