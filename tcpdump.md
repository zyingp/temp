
I found a buffer overread problem in the `print_prefix` function of print-hncp.c. 

Set a breakpoint at the `print_prefix` function, and run tcpdump like 
    tcpdump -ee -vv -nnr id_57.pcap
(The special pcap file could be downloaded from https://github.com/zyingp/temp/blob/master/id_57.pcap)
Then in the `print_prefix` function, the `prefix` variable's value is 0xff, `max_length` is 39, and `is_ipv4_mapped_address` function return `No`. So the program enters the else-clause and called `decode_prefix6` (defined in print-bgp.c). However, the `decode_prefix6` directly returns -1 (since the `plen` in it is 0xff) and does not fill any C string in the passed-in `buf`. Then after back to the `print_prefix` function, since the `buf` variable is not initialized, so the last `ND_PRINT("%s", buf)` in `print_prefix` **may overread the 46-byte-long buffer** `buf` (until meets a '\0' byte).  

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

I found the problem by fuzzing with ASan, and the bug can be reproduced in ASan with 32-bit  tcpdump executable like below.
Prepare env.
```
    dpkg --add-architecture i386
    sudo apt-get install clang-3.5:i386 libclang-3.5-dev:i386
    sudo ln -s /usr/bin/clang-3.5 clang
    sudo ln -s /usr/bin/clang++-3.5 clang++
    sudo apt-get install gcc:i386 g++:i386 make:i386
    sudo apt install flex:i386 bison:i386
```    
Install libpcap
```
    CC=gcc CFLAGS="-m32" LDFLAGS="-m32" ./configure
    sudo make install
```    
Build latest tcpdump
```
    CXX=clang++ CC=clang CFLAGS="-g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-g -fsanitize=address -fno-omit-frame-pointer" ./configure
    make
```    
Then run ` ./tcpdump -ee -vv -nnr id_57.pcap`  get things like below:
```
root@ubuntu4:~# ASAN_OPTIONS=symbolize=1 ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.5 /root/target/tcpdump-master/tcpdump -ee -vv -nnr /mnt/ramdisk/syncdir/fuzzer3/crashes/id:000057,sig:06,src:014587,op:havoc,rep:2
reading from file /mnt/ramdisk/syncdir/fuzzer3/crashes/id:000057,sig:06,src:014587,op:havoc,rep:2, link-type EN10MB (Ethernet), snapshot length 32983
[Invalid header: len(16) < caplen(78)]
05:52:49.892740 08:00:27:da:8f:95 > 33:33:00:00:ff:fe, ethertype IPv6 (0x86dd), length 32929: truncated-ip6 - 32511 bytes missing!(flowlabel 0x0fdff, hlim 0, next-header UDP (17) payload length: 65386) 80ff:ff00::a00:6873:7570:6c6f.8231 > 7274:a43:6f70:7972:6967:6874:3328:6329.14648: hncp (13861)
        Future use: type=13312 (12)
        Unassigned: type=128 (4)
=================================================================
==12256==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xff98608e at pc 0x0808e46d bp 0xff985d88 sp 0xff985940
READ of size 53 at 0xff98608e thread T0
    #0 0x808e46c in printf_common(void*, char const*, char*) (/root/target/tcpdump-master/tcpdump+0x808e46c)
    #1 0x80f1440 in __asan_report_error (/root/target/tcpdump-master/tcpdump+0x80f1440)
    #2 0x808dc11 in printf_common(void*, char const*, char*) (/root/target/tcpdump-master/tcpdump+0x808dc11)
    #3 0x808e8e3 in __interceptor_vfprintf (/root/target/tcpdump-master/tcpdump+0x808e8e3)
    #4 0x812e842 in ndo_printf /root/target/tcpdump-master/./print.c:515:8
    #5 0x8659a70 in print_prefix /root/target/tcpdump-master/./print-hncp.c:236:5
    #6 0x86540cb in hncp_print_rec /root/target/tcpdump-master/./print-hncp.c:740:22
    #7 0x864c4e0 in hncp_print /root/target/tcpdump-master/./print-hncp.c:54:5
    #8 0x8422a55 in udp_print /root/target/tcpdump-master/./print-udp.c:648:4
    #9 0x81f6081 in ip6_print /root/target/tcpdump-master/./print-ip6.c:350:4
    #10 0x81b44a8 in ethertype_print /root/target/tcpdump-master/./print-ether.c:351:3
    #11 0x81b1d92 in ether_print /root/target/tcpdump-master/./print-ether.c:247:7
    #12 0x81b792b in ether_if_print /root/target/tcpdump-master/./print-ether.c:273:10
    #13 0x812c892 in pretty_print_packet /root/target/tcpdump-master/./print.c:389:11
    #14 0x8124b09 in print_packet /root/target/tcpdump-master/./tcpdump.c:2957:2
    #15 0x89248e9 in pcap_offline_read (/root/target/tcpdump-master/tcpdump+0x89248e9)
    #16 0x89114d3 in pcap_loop (/root/target/tcpdump-master/tcpdump+0x89114d3)
    #17 0x811568b in main /root/target/tcpdump-master/./tcpdump.c:2411:12
    #18 0xf74f7636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)
    #19 0x810a750 in _start (/root/target/tcpdump-master/tcpdump+0x810a750)

Address 0xff98608e is located in stack of thread T0 at offset 142 in frame
    #0 0x8658c8f in print_prefix /root/target/tcpdump-master/./print-hncp.c:207

  This frame has 8 object(s):
    [16, 20) ''
    [32, 36) ''
    [48, 52) ''
    [64, 68) ''
    [80, 84) 'plenbytes'
    [96, 142) 'buf'
    [176, 180) 'addr' <== Memory access at offset 142 partially underflows this variable
    [192, 196) 'plen' <== Memory access at offset 142 partially underflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ??:0 printf_common(void*, char const*, char*)
Shadow bytes around the buggy address:
  0x3ff30bc0: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 04 f2
  0x3ff30bd0: 04 f2 04 f2 04 f3 00 00 00 00 00 00 00 00 00 00
  0x3ff30be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30c00: f1 f1 04 f2 04 f2 04 f2 04 f2 04 f2 00 00 00 00
=>0x3ff30c10: 00[06]f2 f2 f2 f2 04 f2 04 f3 00 00 00 00 00 00
  0x3ff30c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff30c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  ASan internal:           fe
==12256==ABORTING
root@ubuntu4:~# 
```

