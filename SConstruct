#!/usr/bin/evn python
import sys
env = Environment(CCFLAGS='-Wall -g', CPPFLAGS='-D_GNU_SOURCE')
platform = sys.platform
lib_path = ['/usr/local/lib', '/usr/lib']
libs = Glob('./*.a') + ['pcap']
cpp_path=['.']

if platform == 'darwin':
      env.Append(CPPFLAGS=['-Ddarwin'])

# Compile the programs
env.Program(target = './pkt2flow', 
			source = Glob('./*.c'),
			LIBPATH = lib_path,
			LIBS = libs,
			CPPPATH = cpp_path)
