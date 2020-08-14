import csv
import math
import decimal as dec
import scipy.stats

######### Modify Parameters Here #########
# file parameter
exact_dir_path = 'Exact_Result_Directory/'
est_dir_path = 'Estimation_Result_Directory/'
mode = 'sec'
time_interval = '30s'
pcap = ['trace_1.pcap']

# statistic parameter
output_file_name = 'Output_File_Name.csv'
title = ['type', 'srcIP', 'dstIP', 'sport', 'dport', 'proto', 'pktLen']
algorithm_name = 'Algorithm_1'
##########################################


# cal parameter
classifiation_reserved_digits = 2
dec.getcontext().prec = classifiation_reserved_digits


def get_KL(est_dir_path):
    # calculation parameter
    exact_srcIP_entropy = []
    exact_dstIP_entropy = []
    exact_sport_entropy = []
    exact_dport_entropy = []
    exact_pktLen_entropy = []
    exact_proto_entropy = []

    est_srcIP_entropy = []
    est_dstIP_entropy = []
    est_sport_entropy = []
    est_dport_entropy = []
    est_pktLen_entropy = []
    est_proto_entropy = []

    deviation_srcIP_value = []
    deviation_dstIP_value = []
    deviation_sport_value = []
    deviation_dport_value = []
    deviation_pktLen_value = []
    deviation_proto_value = []

    # read csv
    ## exact
    for item in pcap:
        file_name = 'Analysis_'+ mode + '_' + time_interval + '_' + item
        with open(exact_dir_path+file_name+'/'+file_name+'.csv', newline='') as fin:
            rows = csv.reader(fin)
            for row in rows:
                try:
                    exact_srcIP_entropy.append(dec.Decimal(row[1]))
                    exact_dstIP_entropy.append(dec.Decimal(row[3]))
                    exact_sport_entropy.append(dec.Decimal(row[5]))
                    exact_dport_entropy.append(dec.Decimal(row[7]))
                    exact_pktLen_entropy.append(dec.Decimal(row[11]))
                    exact_proto_entropy.append(dec.Decimal(row[9]))
                except dec.InvalidOperation:
                    # text does not accept
                    pass

    ## est
    for item in pcap:
        file_name = 'Analysis_'+ mode + '_' + time_interval + '_' + item
        with open(est_dir_path+file_name+'/'+file_name+'.csv', newline='') as fin:
            rows = csv.reader(fin)
            for row in rows:
                try:
                    est_srcIP_entropy.append(dec.Decimal(row[1]))
                    est_dstIP_entropy.append(dec.Decimal(row[3]))
                    est_sport_entropy.append(dec.Decimal(row[5]))
                    est_dport_entropy.append(dec.Decimal(row[7]))
                    est_pktLen_entropy.append(dec.Decimal(row[11]))
                    est_proto_entropy.append(dec.Decimal(row[9]))
                except dec.InvalidOperation:
                    # text does not accept
                    pass

    # calculate deviation
    ## entropy deviation
    for i in range(len(est_srcIP_entropy)):
        try: deviation_srcIP_value.append(est_srcIP_entropy[i]-exact_srcIP_entropy[i])
        except TypeError: pass
        
        try: deviation_dstIP_value.append(est_dstIP_entropy[i]-exact_dstIP_entropy[i])
        except TypeError: pass
        
        try: deviation_sport_value.append(est_sport_entropy[i]-exact_sport_entropy[i])
        except TypeError: pass

        try: deviation_dport_value.append(est_dport_entropy[i]-exact_dport_entropy[i])
        except TypeError: pass

        try: deviation_pktLen_value.append(est_pktLen_entropy[i]-exact_pktLen_entropy[i])
        except TypeError: pass

        try: deviation_proto_value.append(est_proto_entropy[i]-exact_proto_entropy[i])
        except TypeError: pass

    # cal classification items function
    def cnt_classify(data):
        part = 10**classifiation_reserved_digits
        classification = [0.0001,]*part*2 + [0.0001]
        
        for item in data:
            if item > 1: item = dec.Decimal(1)
            if item < -1: item = dec.Decimal(-1)
            key = int(item*part) + part
            classification[key] += 1
        
        len_data = len(data)

        classification = [ item/len_data for item in classification ]
        
        return classification

    # cal KL distance
    def cal_average_KL_scipy(a, b):
        distance_ab = scipy.stats.entropy(pk=a, qk=b, base=2)
        distance_ba = scipy.stats.entropy(pk=b, qk=a, base=2)
        return ((distance_ab+distance_ba)/2)
    
    return dict(
        srcIP=cal_average_KL_scipy( cnt_classify(deviation_srcIP_value), cnt_classify([0,]*len(deviation_srcIP_value)) ),
        dstIP=cal_average_KL_scipy( cnt_classify(deviation_dstIP_value), cnt_classify([0,]*len(deviation_dstIP_value)) ),
        sport=cal_average_KL_scipy( cnt_classify(deviation_sport_value), cnt_classify([0,]*len(deviation_sport_value)) ),
        dport=cal_average_KL_scipy( cnt_classify(deviation_dport_value), cnt_classify([0,]*len(deviation_dport_value)) ),
        proto=cal_average_KL_scipy( cnt_classify(deviation_proto_value), cnt_classify([0,]*len(deviation_proto_value)) ),
        pktLen=cal_average_KL_scipy( cnt_classify(deviation_pktLen_value), cnt_classify([0,]*len(deviation_pktLen_value)) )
    )


# output csv
with open(output_file_name, 'w', encoding='utf-8') as fout:
    writer = csv.writer(fout, delimiter=',')
    writer.writerow(title)
    
    mydata = get_KL(est_dir_path)
    csv_data = [ 
        algorithm_name, mydata['srcIP'], mydata['dstIP'], mydata['sport'], 
                        mydata['dport'], mydata['proto'], mydata['pktLen'] 
    ]
    writer.writerow(csv_data)
