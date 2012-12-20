#!/usr/bin/evn python
env = Environment(CCFLAGS='-w -g')
lib_path = ['/usr/local/lib', '/usr/lib']
libs = Glob('./*.a') + ['pcap']
cpp_path=['.']

# Compile the programs
env.Program(target = './pkt2flow', 
			source = Glob('./*.c'),
			LIBPATH = lib_path,
			LIBS = libs,
			CPPPATH = cpp_path)