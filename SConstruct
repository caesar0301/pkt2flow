#!/usr/bin/evn python
env = Environment(CCFLAGS='-Wall -g', CPPFLAGS='-D_GNU_SOURCE')
lib_path = ['/usr/local/lib', '/usr/lib']
libs = Glob('./*.a') + ['pcap']
cpp_path=['.']

# Compile the programs
env.Program(target = './pkt2flow', 
			source = Glob('./*.c'),
			LIBPATH = lib_path,
			LIBS = libs,
			CPPPATH = cpp_path)
