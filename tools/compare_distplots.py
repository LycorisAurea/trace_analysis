import csv
import plotly
import plotly.figure_factory as ff

######### Modify Parameters Here #########
# plot parameter
output_file_name = 'Output_File_Name.html'
chart_title = 'Your Chart Title'

# file parameter
exact_dir_path = 'Exact_Result_Directory/'
est_dir_path = 'Estimation_Result_Directory/'
mode = 'sec'
time_interval = '30s'
pcap = ['trace_1.pcap']
##########################################



# plot parameter
colors = ['rgba(0,0,255,1)', 'rgba(255,0,0,1)', 'rgba(34,177,76,1)', 
            'rgba(153,51,255,1)', 'rgba(255,128,0,1)', 'rgba(204,204,0,1)']

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

deviation_percent_srcIP_value = []
deviation_percent_dstIP_value = []
deviation_percent_sport_value = []
deviation_percent_dport_value = []
deviation_percent_pktLen_value = []
deviation_percent_proto_value = []



# read csv
## exact
for item in pcap:
    file_name = 'Analysis_'+ mode + '_' + time_interval + '_' + item
    with open(exact_dir_path+file_name+'/'+file_name+'.csv', newline='') as fin:
        rows = csv.reader(fin)
        for row in rows:
            try:
                exact_srcIP_entropy.append(float(row[1]))
                exact_dstIP_entropy.append(float(row[3]))
                exact_sport_entropy.append(float(row[5]))
                exact_dport_entropy.append(float(row[7]))
                exact_pktLen_entropy.append(float(row[11]))
                exact_proto_entropy.append(float(row[9]))
            except ValueError:
                # text does not accept
                pass

## est
for item in pcap:
    file_name = 'Analysis_'+ mode + '_' + time_interval + '_' + item
    with open(est_dir_path+file_name+'/'+file_name+'.csv', newline='') as fin:
        rows = csv.reader(fin)
        for row in rows:
            try:
                est_srcIP_entropy.append(float(row[1]))
                est_dstIP_entropy.append(float(row[3]))
                est_sport_entropy.append(float(row[5]))
                est_dport_entropy.append(float(row[7]))
                est_pktLen_entropy.append(float(row[11]))
                est_proto_entropy.append(float(row[9]))
            except ValueError:
                # text does not accept
                pass

# calculate deviation
## entropy deviation
for i in range(len(est_srcIP_entropy)):
    try: deviation_srcIP_value.append(est_srcIP_entropy[i]-exact_srcIP_entropy[i])
    except TypeError: deviation_srcIP_value.append(None)
    
    try: deviation_dstIP_value.append(est_dstIP_entropy[i]-exact_dstIP_entropy[i])
    except TypeError: deviation_dstIP_value.append(None)
    
    try: deviation_sport_value.append(est_sport_entropy[i]-exact_sport_entropy[i])
    except TypeError: deviation_sport_value.append(None)

    try: deviation_dport_value.append(est_dport_entropy[i]-exact_dport_entropy[i])
    except TypeError: deviation_dport_value.append(None)

    try: deviation_pktLen_value.append(est_pktLen_entropy[i]-exact_pktLen_entropy[i])
    except TypeError: deviation_pktLen_value.append(None)

    try: deviation_proto_value.append(est_proto_entropy[i]-exact_proto_entropy[i])
    except TypeError: deviation_proto_value.append(None)
## percent deviation
for i in range(len(est_srcIP_entropy)):
    try: deviation_percent_srcIP_value.append(deviation_srcIP_value[i] / exact_srcIP_entropy[i])
    except TypeError: deviation_percent_srcIP_value.append(None)
    except ZeroDivisionError: deviation_percent_srcIP_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])
    
    try: deviation_percent_dstIP_value.append(deviation_dstIP_value[i] / exact_dstIP_entropy[i])
    except TypeError: deviation_percent_dstIP_value.append(None)
    except ZeroDivisionError: deviation_percent_dstIP_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])
    
    try: deviation_percent_sport_value.append(deviation_sport_value[i] / exact_sport_entropy[i])
    except TypeError: deviation_percent_sport_value.append(None)
    except ZeroDivisionError: deviation_percent_sport_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])

    try: deviation_percent_dport_value.append(deviation_dport_value[i] / exact_dport_entropy[i])
    except TypeError: deviation_percent_dport_value.append(None)
    except ZeroDivisionError: deviation_percent_dport_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])

    try: deviation_percent_pktLen_value.append(deviation_pktLen_value[i] / exact_pktLen_entropy[i])
    except TypeError: deviation_percent_pktLen_value.append(None)
    except ZeroDivisionError: deviation_percent_pktLen_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])

    try: deviation_percent_proto_value.append(deviation_proto_value[i] / exact_proto_entropy[i])
    except TypeError: deviation_percent_proto_value.append(None)
    except ZeroDivisionError: deviation_percent_proto_value.append(deviation_srcIP_value[i] - exact_srcIP_entropy[i])


# calculate distribution percent
def dis_percent(data):
    new_data = []
    for i in data:
        try: new_data.append( abs(i) )
        except TypeError: pass # ignore None
    new_data = sorted(new_data)

    # x axis, delete repeat items
    x_cdf_data = sorted( list( set(new_data) ) )
    
    # y axis
    y_cdf_data = []
    index = 0
    new_data_count = len(new_data)
    for i in x_cdf_data:
        appear_times = new_data.count(i)
        index += appear_times
        y_cdf_data.append( index/new_data_count*100 )
    
    return (x_cdf_data, y_cdf_data)

entropy_error_dis_percent = dict(
    srcIP=dis_percent(deviation_srcIP_value), 
    dstIP=dis_percent(deviation_dstIP_value),
    sport=dis_percent(deviation_sport_value),
    dport=dis_percent(deviation_dport_value),
    proto=dis_percent(deviation_proto_value),
    pktLen=dis_percent(deviation_pktLen_value)
)
entropy_error_percent_dis_percent = dict(
    srcIP=dis_percent(deviation_percent_srcIP_value), 
    dstIP=dis_percent(deviation_percent_dstIP_value),
    sport=dis_percent(deviation_percent_sport_value),
    dport=dis_percent(deviation_percent_dport_value),
    proto=dis_percent(deviation_percent_proto_value),
    pktLen=dis_percent(deviation_percent_pktLen_value)
)

# calculate average and standard deviation
def get_ave_sd(data):
    summ = 0
    sum_sqrt = 0
    cnt = 0
    for value in data:
        if value != None: 
            summ += value
            sum_sqrt += value**2
            cnt += 1
    average = summ / cnt
    sd = sum_sqrt - (cnt*(average**2))
    return (average, sd)



# plot
## distplot
hist_data = [
    deviation_srcIP_value, deviation_dstIP_value, deviation_sport_value, 
    deviation_dport_value, deviation_pktLen_value, deviation_proto_value
]
group_labels = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Packet Length', 'Protocol']

### remove the same items
for data, label, color in zip(hist_data, group_labels, colors):
    if len( set(data) ) == 1:
        hist_data.remove(data)
        group_labels.remove(label)
        colors.remove(color)

fig_distplot = ff.create_distplot(hist_data[::-1], group_labels[::-1], bin_size=0.001, colors=colors[::-1])
fig_distplot.update_layout(title_text='Distplot_'+chart_title, xaxis=dict(title='Error (Entropy Deviation)', range=[-1,1]), 
                    yaxis=dict(title='Permil (‰)'))
plotly.offline.plot(fig_distplot , filename='Distplot_'+output_file_name, auto_open=False)


## cdf
cdf_data = [
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['srcIP'][0], y=entropy_error_dis_percent['srcIP'][1], 
                                name='CDF of Source IP', marker={'color':colors[0]}, fill='tozeroy'),
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['dstIP'][0], y=entropy_error_dis_percent['dstIP'][1], 
                                name='CDF of Destination IP', marker={'color':colors[1]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['sport'][0], y=entropy_error_dis_percent['sport'][1], 
                                name='CDF of Source Port', marker={'color':colors[2]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['dport'][0], y=entropy_error_dis_percent['dport'][1], 
                                name='CDF of Destination Port', marker={'color':colors[3]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['pktLen'][0], y=entropy_error_dis_percent['pktLen'][1], 
                                name='CDF of Packet Length', marker={'color':colors[4]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=entropy_error_dis_percent['proto'][0], y=entropy_error_dis_percent['proto'][1], 
                                name='CDF of Protocol', marker={'color':colors[5]}, fill='tozeroy')                             
]

cdf_layout = plotly.graph_objs.Layout(
    title='CDF_'+chart_title,
    xaxis=dict(title='Error (Entropy Deviation)', range=[0,1]), 
    yaxis=dict(title='Cumulative Percentage (%)'), 
    bargap=0
)
plotly.offline.plot(
    {'data': cdf_data, 'layout': cdf_layout}, 
    filename='CDF_'+output_file_name, 
    auto_open=False
)


## distplot (percent)
hist_data = [
    [i*100 for i in deviation_percent_srcIP_value], [i*100 for i in deviation_percent_dstIP_value], 
    [i*100 for i in deviation_percent_sport_value], [i*100 for i in deviation_percent_dport_value], 
    [i*100 for i in deviation_percent_pktLen_value], [i*100 for i in deviation_percent_proto_value]
]
group_labels = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Packet Length', 'Protocol']

### remove the same items
for data, label, color in zip(hist_data, group_labels, colors):
    if len( set(data) ) == 1:
        hist_data.remove(data)
        group_labels.remove(label)
        colors.remove(color)

fig_distplot = ff.create_distplot(hist_data[::-1], group_labels[::-1], bin_size=0.001, colors=colors[::-1])
fig_distplot.update_layout(title_text='Distplot_percent_'+chart_title, xaxis=dict(title='Error Percentage(Entropy Deviation %)', range=[-100,100]), 
                            yaxis=dict(title='Permil (‰)'))
plotly.offline.plot(fig_distplot , filename='Distplot_percent_'+output_file_name, auto_open=False)


## cdf (percent)
cdf_data = [
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['srcIP'][0]], y=entropy_error_percent_dis_percent['srcIP'][1], 
                                name='CDF of Source IP', marker={'color':colors[0]}, fill='tozeroy'),
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['dstIP'][0]], y=entropy_error_percent_dis_percent['dstIP'][1], 
                                name='CDF of Destination IP', marker={'color':colors[1]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['sport'][0]], y=entropy_error_percent_dis_percent['sport'][1], 
                                name='CDF of Source Port', marker={'color':colors[2]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['dport'][0]], y=entropy_error_percent_dis_percent['dport'][1], 
                                name='CDF of Destination Port', marker={'color':colors[3]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['pktLen'][0]], y=entropy_error_percent_dis_percent['pktLen'][1], 
                                name='CDF of Packet Length', marker={'color':colors[4]}, fill='tozeroy'), 
    plotly.graph_objs.Scatter(x=[i*100 for i in entropy_error_percent_dis_percent['proto'][0]], y=entropy_error_percent_dis_percent['proto'][1], 
                                name='CDF of Protocol', marker={'color':colors[5]}, fill='tozeroy')                             
]

cdf_layout = plotly.graph_objs.Layout(
    title='CDF_percent_'+chart_title,
    xaxis=dict(title='Error Percentage(Entropy Deviation %)', range=[0,100]), 
    yaxis=dict(title='Cumulative Percentage (%)'), 
    bargap=0
)
plotly.offline.plot(
    {'data': cdf_data, 'layout': cdf_layout}, 
    filename='CDF_percent_'+output_file_name, 
    auto_open=False
)

# write txt
with open(output_file_name+'.txt', 'w') as fout:
    fout.write('Average / Standard Diviation\n\n')
    fout.write('Distplot_'+output_file_name+'\n')
    fout.write('Source IP:' + str(get_ave_sd(deviation_srcIP_value)) + '\n')
    fout.write('Destination IP:' + str(get_ave_sd(deviation_dstIP_value)) + '\n')
    fout.write('Source Port:' + str(get_ave_sd(deviation_sport_value)) + '\n')
    fout.write('Destination Port:' + str(get_ave_sd(deviation_dport_value)) + '\n')
    fout.write('Packet Length:' + str(get_ave_sd(deviation_pktLen_value)) + '\n')
    fout.write('Protocol:' + str(get_ave_sd(deviation_proto_value)) + '\n')

    fout.write('\n\n')

    fout.write('Distplot_percent_'+output_file_name+'\n')
    fout.write('Source IP:' + str(get_ave_sd(deviation_percent_srcIP_value)) + '\n')
    fout.write('Destination IP:' + str(get_ave_sd(deviation_percent_dstIP_value)) + '\n')
    fout.write('Source Port:' + str(get_ave_sd(deviation_percent_sport_value)) + '\n')
    fout.write('Destination Port:' + str(get_ave_sd(deviation_percent_dport_value)) + '\n')
    fout.write('Packet Length:' + str(get_ave_sd(deviation_percent_pktLen_value)) + '\n')
    fout.write('Protocol:' + str(get_ave_sd(deviation_percent_proto_value)) + '\n')
    