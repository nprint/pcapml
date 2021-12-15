from distutils.core import setup, Extension

pcapml_FE = Extension(name='pcapml_FE',
                     define_macros = [('MAJOR_VERSION', '0'),
                                      ('MINOR_VERSION', '1')],

                     include_dirs=['../include/', '../include/dir/', '../include/label',
                                   '../include/sample/', '../include/pcap/',
                                   '../include/pcapng/'],
                     libraries=['pcap', 'stdc++'],
                     sources=['pcapml_pymod.cpp', '../src/pcapng/block_pcapng.cpp',
                              '../src/pcapng/reader_pcapng.cpp', '../src/pcapng/sorter_pcapng.cpp',
                              '../src/util.cpp', '../src/sample/sampler.cpp',
                              '../src/sample/sample.cpp']
                    )

setup(name="pcapml_FE",
      version="0.0.1",
      description="Python interface for pcapML",
      author="nPrint",
      author_email="nprint.pr@gmail.com",
      ext_modules=[pcapml_FE]
     )
