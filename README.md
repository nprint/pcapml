# pcapml

`pcapml` standardizes network traffic analysis tasks, improving reproducability by directly coupling metadata and raw traffic traces. On the dataset curation side, pcapml enables researchers to directly encode metadata into raw traffic traces in such a way that classic libraries and tools such as `tcpdump` and `tshark` can still be leveraged. On the analysis side, `pypcapml` leverages the standardized format, exposing a python interface that reads metadata-encoded pcapml output, enabling the user to focus on extracting interesting information from traffic sequences. 

There will be bugs! Please report any you see.

# Walkthrough

## Dataset Curation

`pcpaml` standardizes network traffic analysis tasks at the _dataset level_. Rather than focus on a standardized methodology, feature set, or library for combining traffic traces and metadata (such as labels for machine learning tasks), pcapml provides a system for directly coupling raw traffic traces and metadata by using the Next Generation PCAP (`pcpang`) format. `pcapng` files can still be read by libraries such as `libpcap`, and inspected using tools such as `tcpdump` or `tshark`. Whereas a `pcap` represents a linked-list of packets, a `pcapng` represents a linked list of _blocks_, which we can use to directly couple packet data and metadata. 

pcapml attaches a **sampleID** to each packet, enabling us to group packets arbitrarily. By grouping packets arbitrarily, we can attach metadata to traffic flows, devices, applications, anomalies, individual packets, attacks, time windows, or any other interesting grouping. pcapml can currently attach metadata in two ways. First, it can attach a sampleID and metadata to a directory of `pcap`s, one traffic sample per file. Second, it can attach metadata to traffic in a single `pcap` using bpf filters, timestamps, or any combination of the two. 

We walk through a quick example using the [snowflake fingeprintability dataset](https://github.com/kyle-macmillan/snowflake_fingerprintability). This dataset contains a set of DTLS handshakes from four applications, Facebook Messenger, Discord, Google Hangouts, and Snowflake. Each handshake was gathered to understand if Snowflake could be uniqeuly identified from the other services. 

We can label each handshake in the dataset with a _sampleID_ and its corresponding application label in a metadata-encoded `pcapng` with the command

`pcapml -D dataset/ -L labels.txt -W snowflake-labeled-dataset.pcapng`

where the datset directory contains the `pcaps` and the labels file looks as follows:

```
filename,label
facebook-handshake-1.pcap,facebook
discord-handshake-1.pcap,discord
....
```

This results in a `pcapng` that can be examined with `tcpdump`.

```
$ tcpdump -r dtls-dataset.pcapng -c 10
reading from file dtls-dataset.pcapng, link-type EN10MB (Ethernet)
12:58:52.562021 IP 74.125.250.71.19305 > 192.168.7.222.55937: UDP, length 161
12:58:52.562788 IP 192.168.7.222.55937 > 74.125.250.71.19305: UDP, length 618
12:58:52.585452 IP 74.125.250.71.19305 > 192.168.7.222.55937: UDP, length 1119
12:58:52.586333 IP 192.168.7.222.55937 > 74.125.250.71.19305: UDP, length 962
13:07:34.459150 IP 74.125.250.26.19305 > 192.168.7.222.54537: UDP, length 161
13:07:34.460771 IP 192.168.7.222.54537 > 74.125.250.26.19305: UDP, length 617
13:07:34.486225 IP 74.125.250.26.19305 > 192.168.7.222.54537: UDP, length 1119
13:07:34.487034 IP 192.168.7.222.54537 > 74.125.250.26.19305: UDP, length 962
17:12:42.435787 IP 74.125.250.71.19305 > 192.168.7.222.54510: UDP, length 161
17:12:42.438214 IP 192.168.7.222.54510 > 74.125.250.71.19305: UDP, length 705
```

Upon further inspection using `tshark`, we see the _sampleID_ and label directly encoded in the output file, where each handshake receives a unique `sampleID`, leaving no ambiguity on how the metadata is attached to the traffic.

```
jordan@jordan-NUC8i7BEH:~/research/pcapml/labeled-datasets$ tshark -r dtls-dataset.pcapng -T fields  -E header=y -e frame.comment -c 10
frame.comment
9003219589747928972,google
9003219589747928972,google
9003219589747928972,google
9003219589747928972,google
18186043603218801379,google
18186043603218801379,google
18186043603218801379,google
18186043603218801379,google
14792257769479651673,google
14792257769479651673,google
```

Any arbitrary grouping of packets can be named, enabling us to group packets by application, flows, device, attacks, or any other common traffic analysis task. We also note that this _sampleID_ enables easy benchmarking for popular datasets: the only information that needs to be published is the dataset and a list of training, testing, and challenge _sampleIDs_ for users with different methods to compare with each other.

## Analysis

`pcapml` output can be read by tools such as `tshark` or `tcpudmp`. We realize that the crux of traffic analysis tasks involves extracting identifying information from traffic samples. pcapml's standardized output format allows us to focus on extracting features by exposing a python iterator to pcapml labeled datasets. `pypcapml` removes the barrier to entry for traffic analysis tasks, enabling a) users to focus on methods for information extraction b) write one feature extraction method for multiple datasets and c) create more reproducable pipelines for future work to comapre with. An example of using `pypcapml` is below:

```python
import argparse

import pcapML

def main():
    '''
    Reads a pcapng file labeled and sorted with pcapml, presenting traffic samples to 
    the user for features to be extracted from. To test the method on a new dataset
    the only needed change is to load in a different dataset
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapml_dataset')
    args = parser.parse_args()
    
    for traffic_sample in pcapML.sampler(args.pcapml_dataset):
        extract_info(traffic_sample)

def extract_info(traffic_sample):
    '''
    Each sample contains the sampleID, metadata and a list of packets 
    with their associated timestamps
    '''
    sid = traffic_sample[0][1]
    metadata = traffic_sample[0][2]

    print(sid, len(traffic_sample), metadata)
    '''
    iterating over the traffic sample (packets and timestamps)
    Assuming you've imported scapy as 'import scapy.all as scapy'
    you can transform to Scapy packets with 'scapy.Ether(pkt_buf)'
    '''
    for idx, sid, label, ts, pkt_buf in traffic_sample:
        # Extract features
        pass
```

# Installation

### Supported Operating Systems

* Debian Linux
* macOS

### Dependencies

* libpcap - Packet sniffing
* argp - Argument parsing

Install dependencies on Debian: `sudo apt-get install libpcap-dev`

Install dependencies on Mac OS: `brew install argp-standalone`

### Install

1. Download the latest release tar here

2. Extract the tar `tar -xvf pcapml-[version].tar.gz`

3. `cd [pcapml-directory]`

4. `./configure && make && sudo make install`


# Installing pypcapml

Current instructions:

1. clone repository: `git clone [pcapml]`
2. move to pypcapml directory: `cd pcapml/pypacpml`
3. run setup: `python setup.py install`
