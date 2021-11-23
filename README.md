# pcapml

`pcapml` standardizes network traffic analysis tasks, improving reproducability by directly coupling metadata and raw traffic traces. On the dataset curation side, pcapml enables researchers to directly encode metadata into raw traffic traces in such a way that classic libraries and tools such as `tcpdump` and `tshark` can still be leveraged. On the analysis side, `pypcapml` leverages the standardized format, exposing a python interface that reads metadata-encoded pcapml output, enabling the user to focus on extracting interesting information from traffic sequences. 

There will be bugs! Please report any you see.

# Installation

## Supported Operating Systems

* Debian Linux
* macOS

## Dependencies

* [libpcap](https://www.tcpdump.org/) - Packet sniffing
* [argp](https://www.gnu.org/software/libc/manual/html_node/Argp.html) - Argument parsing

### Install dependencies on Debian:

`sudo apt-get install libpcap-dev`

### Install dependencies on Mac OS

`brew install argp-standalone`

## Installation

1. Download the latest release tar [here](https://github.com/nprint/pcapml/releases/)
2. Extract the tar `tar -xvf [pcapml-version.tar.gz]`
3. `cd [pcapml-directory]`

2. `./configure && make && sudo make install`

# Walkthrough

## Dataset Curation

`pcpaml` standardizes network traffic analysis tasks at the _dataset level_. Rather than focus on a standardized methodology, feature set, or library for combining traffic traces and metadata (such as labels for machine learning tasks), pcapml provides a system for directly coupling raw traffic traces and metadata by using the Next Generation PCAP (`pcpang`) format. `pcapng` files can still be read by libraries such as `libpcap`, and inspected using tools such as `tcpdump` or `tshark`. Whereas a `pcap` represents a linked-list of packets, a `pcapng` represents a linked list of _blocks_, which we can use to directly couple packet data and metadata. 

pcapml attaches a **sampleID** to each packet, enabling us to group packets arbitrarily. By grouping packets arbitrarily, we can attach metadata to traffic flows, devices, applications, anomalies, individual packets, attacks, time windows, or any other interesting grouping. pcapml can currently attach metadata in two ways. First, it can attach a sampleID and metadata to a directory of `pcap`s, one traffic sample per file. Second, it can attach metadata to traffic in a single `pcap` using bpf filters, timestamps, or any combination of the two. 

We walk through a quick example using the [snowflake fingeprintability dataset](https://github.com/kyle-macmillan/snowflake_fingerprintability). This dataset contains a set of DTLS handshakes from four applications, Facebook Messenger, Discord, Google Hangouts, and Snowflake. Each handshake was gathered to understand if Snowflake could be uniqeuly identified from the other services. 

We can label each handshake in the dataset with a _sampleID_ and its corresponding application label in a metadata-encoded `pcapng` with the command

`$ pcapml -D dataset/ -L labels.txt -W snowflake-labeled-dataset.pcapng`

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
$ tshark -r dtls-dataset.pcapng -T fields  -E header=y -e frame.comment -c 10
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

Any arbitrary grouping of packets can be used, enabling us to group packets by application, flows, device, attacks, or any other common traffic analysis task. We also note that this _sampleID_ enables easy benchmarking for popular datasets: the only information that needs to be published is the dataset and a list of training, testing, and challenge _sampleIDs_ for users with different methods to compare with each other.

## Transforming PCAPNGs back to PCAPs

`pcapml` can transform pcaps encoded with metadata back from the `pcapng` file format into a directory of `pcap` files, one per traffic sample. An example of this is shown below:

`$ pcapml -M dtls-dataset.pcapng -O output_dir/`

The associated output directory is below. Also note that a `metadata.csv` file is generated which maps each individual `pcap` to the metadata associated with the traffic in that file.

```
12868490791586055289_firefox_google.pcap     1567624542436120405_chrome_google.pcap       1912376493094597460_chrome_facebook.pcap     4676138587463220727_chrome_discord.pcap     7254850485921062848_firefox_snowflake.pcap  9982255779078537418_firefox_facebook.pcap
12869046855586552312_chrome_google.pcap      15679484754686191639_firefox_snowflake.pcap  1913144610008489287_firefox_snowflake.pcap   4681195497095943526_chrome_google.pcap      7256930666031261978_chrome_facebook.pcap    9985167304055034928_firefox_discord.pcap
1286997930834027255_firefox_snowflake.pcap   15679812277643271301_firefox_facebook.pcap   1916232746973137357_chrome_discord.pcap      4681553453692518285_firefox_facebook.pcap   7259083765404759561_firefox_google.pcap     9987359559073017848_firefox_discord.pcap
12872114975008852282_firefox_google.pcap     15680488968942900640_firefox_discord.pcap    1923291248933451411_firefox_google.pcap      4682231651136175711_firefox_snowflake.pcap  7270091391588454401_firefox_facebook.pcap   9987474006825771582_firefox_discord.pcap
1287296956060682578_firefox_snowflake.pcap   15684992164591678892_chrome_discord.pcap     1925192065339906372_chrome_discord.pcap      4683353161259521763_chrome_discord.pcap     7275055456267078471_chrome_discord.pcap     9988384164514239661_chrome_discord.pcap
12873202627492535975_firefox_facebook.pcap   15686837623379429946_firefox_snowflake.pcap  1926070980564693651_firefox_facebook.pcap    4686331860154165481_chrome_google.pcap      7275947196122656266_firefox_facebook.pcap   9988671347025180223_chrome_google.pcap
12873382713093872777_chrome_google.pcap      15688281783655954598_firefox_facebook.pcap   1929316700484367743_firefox_google.pcap      4691855233376734243_firefox_facebook.pcap   7277881488664112182_firefox_snowflake.pcap  9997286002475491721_firefox_snowflake.pcap
12873578531244000000_chrome_discord.pcap     15689928502533307139_chrome_discord.pcap     1929370065488740302_firefox_discord.pcap     4692051960365545016_firefox_facebook.pcap   7279922213696870942_firefox_discord.pcap    9999784168933737877_firefox_discord.pcap
12876456759470137409_firefox_facebook.pcap   156906826116949201_firefox_facebook.pcap     1934193991250090531_chrome_facebook.pcap     4693928983586216046_firefox_google.pcap     72814636468293824_chrome_facebook.pcap      metadata.csv
12883035177162246424_firefox_facebook.pcap   15693993440989292713_firefox_google.pcap     193462701501369877_firefox_snowflake.pcap    4694722099231551357_firefox_discord.pcap    7283866935170316498_firefox_discord.pcap
12883375487480703575_chrome_discord.pcap     15699393452417499983_chrome_discord.pcap     1938039119303991228_firefox_google.pcap      4694846922012149593_firefox_google.pcap     7299769344200015575_firefox_snowflake.pcap
```

`$ head metadata.csv`

```
File,Label
14944434813179707824_chrome_google.pcap,chrome_google
14395580548679227705_chrome_google.pcap,chrome_google
14489979562741152699_firefox_google.pcap,firefox_google
870078443570293459_firefox_google.pcap,firefox_google
6809604472343037417_firefox_google.pcap,firefox_google
9649013506394351716_firefox_google.pcap,firefox_google
16984261106149530861_firefox_google.pcap,firefox_google
12493399449979137519_chrome_google.pcap,chrome_google
7073271527767585992_firefox_google.pcap,firefox_google
```

## Analysis

Although `pcapml` output can be read by tools such as `tshark` or `tcpudmp`, we realize that the crux of traffic analysis tasks involves extracting identifying information from traffic samples. pcapml's standardized output format allows us to focus on extracting features by exposing a python iterator to pcapml labeled datasets. `pypcapml` removes the barrier to entry for traffic analysis tasks, enabling:
1. Users to focus on __methods__ for information extraction 
2. Users to write one feature extraction method for multiple datasets, exploring the generality of methods across tasks.
3. More reproducable pipelines for futrure work to benchmark and compare with. ]

An example of using `pypcapml` is below:

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
