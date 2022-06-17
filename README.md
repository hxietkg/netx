# netx

Studying golang for me! :)

***********************************************************************************
***********************************************************************************

This repo is just used for go-lang sutdy, you may use command 'next' to do:

1. List all interfaces in the host:
    ./netx listif

2. Capture packets from a specific interface:
    ./netx rx -i <N>
    ./netx rx --ifname <ifname>

3. arpflood:
    ./netx arpflood -i 4 \
                    --src-mac=00:11:22:33:44:55 \
                    --dest-mac=00:55:44:33:22:11 \
                    --arp-src-mac=00:12:34:56:78:90 \
                    --arp-target-mac=00:90:78:56:34:21 \
                    --arp-src-ip=192.168.11.11 \
                    --arp-target-ip=102.168.11.22 \
                    -c 10

4. pingflood:
    ./netx pingflood -i 4 \
                     --src-mac=00:11:22:33:44:55 \
                     --dest-mac=00:55:44:33:22:11 \
                     --src-ip=192.168.11.11 \
                     --dest-ip=102.168.11.22

5. synflood:
    ./netx synflood -i 4 \
                    --src-mac=00:11:22:33:44:55 \
                    --dest-mac=00:55:44:33:22:11 \
                    --src-ip=192.168.11.11 \
                    --dest-ip=102.168.11.22 \
                    --src-port 11111 \
                    --dest-port=22222

6. tx a packet:
    ./netx tx -i 4 \
              -p 005544332211001122334455080045000032abcd400080061187c0a80b0b66a80b162b6756ce1234567887654321500260005cfe000000000000000000000000


NOTE:
    option '-i' is used to specify an interface by index, the index is the
    order in output of './netx dump -l', you may use option '--ifname' to
    specify an interface by interface name.
