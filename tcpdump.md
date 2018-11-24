I found a buffer overread problem in the print_prefix function of print-hncp.c. 

Run with 
` tcpdump -ee -vv -nnr id_57.pcap` 
(The special pcap file could be downloaded from https://github.com/zyingp/temp/blob/master/id_57.pcap)
In the `print_prefix` function, the program enters the else-clause, however, `decode_prefix6` (defined in print-bgp.c)Since the `buf` variable is not  

```C
static int
print_prefix(netdissect_options *ndo, const u_char *prefix, u_int max_length)
{
    int plenbytes;
    char buf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx::/128")];

    if (EXTRACT_U_1(prefix) >= 96 && max_length >= IPV4_MAPPED_HEADING_LEN + 1 &&
        is_ipv4_mapped_address(prefix + 1)) {
        //... omit some code here
    } else {
        // id_57.pcap enters here
        plenbytes = decode_prefix6(ndo, prefix, max_length, buf, sizeof(buf));
    }

    ND_PRINT("%s", buf);
    return plenbytes;
}        
```     

```C
int
decode_prefix6(netdissect_options *ndo,
               const u_char *pd, u_int itemlen, char *buf, u_int buflen)
{
    struct in6_addr addr;
    u_int plen, plenbytes;

    ND_TCHECK_1(pd);
    ITEMCHECK(1);
    plen = EXTRACT_U_1(pd);
    if (128 < plen)
        return -1;
    //... omit some code here    
}
``` 
