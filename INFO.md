## Network Slicing Info

## $A -$ ★ TODOs

Metrics:
    bps average
	bps max (selecting the max of the samples from the iperf3 test)
	
	Delay jitter
	Losses

iperf3 -c 147.83.39.190 -u -b 1G -l packetsize

ping with different sizes: 100, 200, 400, 800, 1490
Collect all the results
--------------------------------
>> Design the flow of packets from GPU | 
>> Who will generate the packets.
>> No need to checksum (Its done on the Physical layer)
>> No checksum of the IP packets also
 - [x] RTT: channel using ping
 - [x] Delay (taken from RTT/2 using ping)
 - [x] bit rate: avg (bit rate) + peak (bit rate) + std (bit rate)
 - [x] delay and Loses using iperf



 - [x] Verify that you follow the designed model
 - [x] Implement the front-end layer
 - [x] ...
 - [x] Do the performance trial locally
 - [x] Do the performance trial Xavier
 - [x] Check if packet forwarding is working
 - [x] Verify the GPU side of the implementation
 - [x] Draw a diagram of the implementation

## $B -$ ★ DONE

Measure the end to end capacity of the channel 

Do local test with local bandwidth between two Nvidia

Long distance end to end test

Test:

IP:147.83.39.190

Different packet size: 80kb -- 200kb -- 500kb --1024kb

Time: 

Use UDP protocol: More stable to stress the channel and measure the performance.

We want:










