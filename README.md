# Trace Analysis

This project analizes flows of trace files and outputs to charts.

## Sample Output

* Entropy Values
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_1_entropy.png)

* Distinct Counts
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_2_count.png)

* CSV File
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_4_csv.png)

## Dependency

* Linux OS
* The file **_analysis.py_** uses python3.5, needs kits: `dpkt` and `plotly`

  ```bash
  sudo apt install python3-pip
  pip3 install dpkt
  pip3 install plotly
  ```

## How To Use

### `Calculating exact entropy values (One Trace File)`

* Usage :

    ```bash
    python3 analysis.py <trace file>  <attack list(or none)> <mode:sec/min/hour/real> <time interval(sec)>
    ```

  * `trace file` : The path of the trace file you want to analysis.
  * `attack list`: The time of attack ranges. If you don't have attack list, you can fill in 'none'. Refer to `attack_list_example.txt` for details.
  * `mode` : The display mode of x-axis showing in charts, csv files. 'real' option will display real packet time in trace files.
  * `time interval` : The time interval range to analysis trace files. The unit is second.

### `Calculating exact entropy values (Several Trace Files)`

Some large trace may be seperated to seveal smaller files. It needs to import method in `analysis.py` to process trace files.

* Usage : Refer to `sep_trace_example.py` for details.

### `Advanced Features`

* Select Output Elements
  * Entropy value - You can select the **6 entropy elements** to output or no : `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Packet Length`, `Protocol`.

    ``` Python
    TracePlot.entropy_one_plot(
    ['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport',
     'entropy_dport', 'entropy_pkt_len', 'entropy_proto']
    )
    ```
  
  * Distinct Count - You can select the **6 distinct count** and **3 count elements** to output or no : `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Packet Length`, `Protocol` and `Packet Count`, `Total Packet Length`, `Average Packet Length`.

    ``` Python
    TracePlot.count_one_plot(
    ['distinct_src_ip', 'distinct_dst_ip', 'distinct_sport',
     'distinct_dport', 'distinct_pkt_len', 'distinct_proto',
     'count_pkt_cnt', 'count_total_pkt_len','count_average_pkt_len']
    )
    ```
