import argparse

import pcapml_FE

def main():
    '''
    Reads a pcapng file labeled and sorted with pcapml, presenting traffic samples to 
    the user for features to be extracted from. To test the method on a new dataset
    the only needed change is to load in a different dataset
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapml_dataset')
    args = parser.parse_args()
    
    for traffic_sample in pcapml_FE.sampler(args.pcapml_dataset):
        extract_info(traffic_sample)

def extract_info(traffic_sample):
    '''
    Each sample contains the sampleID, metadata and a list of packets 
    with their associated timestamps
    '''
 
    '''
    iterating over the traffic sample (packets and timestamps)
    Assuming you've imported scapy as 'import scapy.all as scapy'
    you can transform to Scapy packets with 'scapy.Ether(pkt_buf)'
    '''
    for pkt in traffic_sample:
        print(pkt)
        # Extract features
        pass

if __name__ == '__main__':
    main()
