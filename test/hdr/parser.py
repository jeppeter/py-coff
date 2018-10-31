#! /usr/bin/env python


import sys
import os
import extargsparse
import logging

sys.path.append(os.path.join(os.path.dirname(__file__),'..','..','src'))
import coff

def read_binary(infile=None):
	fin = sys.stdin
	if infile is not None:
		fin = open(infile,'rb')
	data = fin.read()
	if 'b' not in fin.mode:
		data = data.encode('utf8')
	if fin != sys.stdin:
		fin.close()
	fin = None
	return data


def set_logging_level(args):
    loglvl= logging.ERROR
    if args.verbose >= 3:
        loglvl = logging.DEBUG
    elif args.verbose >= 2:
        loglvl = logging.INFO
    if logging.root is not None and len(logging.root.handlers) > 0:
        logging.root.handlers = []
    logging.basicConfig(level=loglvl,format='%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d\t%(message)s')
    return



def header_handler(args,parser):
	set_logging_level(args)
	for v in args.subnargs:
		data = read_binary(v)
		hdr = coff.CoffHeader(data)
		sys.stdout.write('%s header %s\n'%(v,hdr))
	sys.exit(0)
	return
def main():
	commandline='''
	{
		"verbose|v" : "+",
		"header<header_handler>" : {
			"$" : "*"
		}
	}
	'''
	parser = extargsparse.ExtArgsParse()
	parser.load_command_line_string(commandline)
	parser.parse_command_line(None,parser)
	raise Exception('can not parse')
	return

if __name__ == '__main__':
	main()
