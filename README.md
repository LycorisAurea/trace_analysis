# Trace Analysis

This project analizes flows of trace files and outputs to charts.

## Dependency

* The file **_analysis.py_** uses python3, needs kits: dpkt, plotly

```bash
sudo apt install python3-pip
pip3 install dpkt
pip3 install plotly
```

## How To Use

### `Calculating exact entropy values`

* Usage :

    ```bash
    python3 analysis.py <trace file>  <attack list(or 'none')> <mode:sec/min/hour/real> <time interval(sec)>
    ```

  * `trace file` : The path of the trace file you want to analysis.
  * `attack list`: The time of attack ranges. If you don't have attack list, you can fill in 'none'.
  * `mode` : The display mode of x-axis showing in charts, csv files. 'real' option will display real packet time in trace files.
  * `time interval` : The time interval range to analysis trace files. The unit is second.

* Sample Output :

  ![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_1.png)
