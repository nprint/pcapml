AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = pcapml

pcapml_SOURCES = include/dir/dir.hpp include/label/label.hpp include/label/labeler.hpp \
				 include/pcap/reader_pcap.hpp include/pcap/writer_pcap.hpp \
				 include/pcapng/block_pcapng.hpp include/pcapng/reader_pcapng.hpp \
				 include/pcapng/sorter_pcapng.hpp include/pcapng/splitter_pcapng.hpp \
				 include/pcapng/writer_pcapng.hpp \
				 include/sample/sample.hpp include/sample/sampler.hpp \
				 include/util.hpp \
				 src/dir/dir.cpp src/label/label.cpp src/label/labeler.cpp \
				 src/pcap/reader_pcap.cpp src/pcap/writer_pcap.cpp \
				 src/pcapng/block_pcapng.cpp src/pcapng/reader_pcapng.cpp \
				 src/pcapng/sorter_pcapng.cpp src/pcapng/splitter_pcapng.cpp \
				 src/pcapng/writer_pcapng.cpp \
				 src/sample/sample.cpp src/sample/sampler.cpp \
				 src/util.cpp src/pcapml.cpp

AM_CPPFLAGS = -I include/ -I include/dir -I include/pcap/ -I include/pcapng -I include/sample -I include/label -pedantic -Wall -std=gnu++11 $(WRAPPER_CPPFLAGS)
AM_LDFLAGS = $(WRAPPER_LDFLAGS)
