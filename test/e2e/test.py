import os
import shutil
import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap')
    parser.add_argument('metadata')
    parser.add_argument('outdir')
    parser.add_argument('-k', '--keep_files', action='store_true')
    args = parser.parse_args()
    
    os.makedirs(args.outdir, exist_ok=True)

    pcapng_test_file = os.path.join(args.outdir, 'test.pcapng')
    pcap_test_file = os.path.join(args.outdir, 'test.pcap')
    label_cmd = 'pcapml -P {0} -L {1} -W {2}'.format(args.pcap, args.metadata,
                                                     pcapng_test_file)
    proc = subprocess.run(label_cmd, shell=True)
    
    strip_cmd = 'pcapml -M {0} -p -W {1}'.format(pcapng_test_file, pcap_test_file)

    proc = subprocess.run(strip_cmd, shell=True)

    og_tcpdump = os.path.join(args.outdir, 'tcpdump_og.txt')
    stripped_tcpdump = os.path.join(args.outdir, 'tcpdump_stripped.txt')

    tcpdump_og_cmd = 'tcpdump -r {0} -nvv  > {1}'.format(args.pcap, og_tcpdump)
    proc = subprocess.run(tcpdump_og_cmd, shell=True)

    tcpdump_stripped_cmd = 'tcpdump -r {0} -nvv > {1}'.format(pcap_test_file, 
                                                              stripped_tcpdump)
    proc = subprocess.run(tcpdump_stripped_cmd, shell=True)

    diff = 'diff tcpdump_og.txt tcpdump_stripped.txt -q -s -y'
    proc = subprocess.run(diff, shell=True, stdout=subprocess.PIPE)
    out = proc.stdout.decode('utf-8')
    
    if 'identical' in out:
        print('PASSED')
        print('  Original pcap and stripped pcapng are identical')
        if not args.keep_files:
            print('  Removing files from test, force keep with `-k`')
            shutil.rmtree(args.outdir)
    else:
        print('FAILED')
        print('  Original pcap and stripped pcapng differ')

if __name__ == '__main__':
    main()
