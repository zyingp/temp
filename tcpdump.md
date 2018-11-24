I found a buffer overread problem in the print_prefix function of print-hncp.c. 

Run with 
` tcpdump -ee -vv -nnr id_57.pcap` 
(The special pcap file could be downloaded from https://github.com/zyingp/temp/blob/master/id_57.pcap)
