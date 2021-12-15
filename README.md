# pcapML

For a project overview, detailed usage information, and installation information please visit [pcapml's project homepage](https://nprint.github.io/pcapml.html)

There will be bugs! Please report any you see.

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

1. Download the latest release tar [here](https://github.com/nprint/pcapml/releases)

2. Extract the tar `tar -xvf pcapml-[version].tar.gz`

3. `cd [pcapml-directory]`

4. `./configure && make && sudo make install`


# Installing pypcapml

Current instructions:

1. clone repository: `git clone [pcapml]`
2. move to pypcapml directory: `cd pcapml/pypacpml`
3. run setup: `python setup.py install`
