# Zeek script to detect covert channels created with [CCgen.v2](https://github.com/CN-TU/CCgen.v2)

### Covert Channels Detected from CCgen.v2
- TTL (dev, r2s and v2s)
- IP Flags (v2s)
- IP Identification (v2s)
- IP Type of Service (nowadays called DSCP) (v2s)
- TCP Urgent Pointer (container)

Use these scripts in conjuction with my [zeek fork](https://github.com/Schmittenberger/ZEEK-TCP-Urgent-Pointer-fork) to detect covert channels using the TCP Urgent Pointer and IP Flags. The basic Zeek version only allows detection of TTL, IP Identification and IP TOS.

#### Quick start

1. Clone this repo:

   ```git clone https://github.com/Schmittenberger/Zeek-CCgen.v2.git```

3. Run & Test the scripts with the provided pcaps, for example:
   
   * if you built zeek from the source repo (https://github.com/zeek/zeek) and with default install dir with make:
     
    ```/usr/local/zeek/bin/zeek -Cr test/baseline-sample.pcap Zeek-CCgen.v2```

  * if you are using my [zeek fork](https://github.com/Schmittenberger/ZEEK-TCP-Urgent-Pointer-fork) and installed it to ```usr/local/zeek-fork```:
    
    ```/usr/local/zeek-fork/bin/zeek -Cr test/baseline-sample.pcap Zeek-CCgen.v2```
    
   
