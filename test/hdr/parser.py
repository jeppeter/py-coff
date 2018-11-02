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

def optheader_handler(args,parser):
	set_logging_level(args)
	for v in args.subnargs:
		data = read_binary(v)
		hdr = coff.CoffHeader(data)
		if hdr.optsize == 0:
			sys.stdout.write('[%s] no opt header\n'%(v))
		else:
			opthdr = coff.CoffOptHeader(data[hdr.size:])
			sys.stdout.write('[%s] optheader %s\n'%(v,opthdr))
	sys.exit(0)
	return

def sections_handler(args,parser):
	set_logging_level(args)
	for v in args.subnargs:
		data = read_binary(v)
		hdr = coff.CoffHeader(data)
		size = hdr.get_size()
		if hdr.optsize != 0:
			size += hdr.optsize
		curoff = size
		sys.stdout.write('[%s] %s\n'%(v,hdr))
		for i in range(hdr.numsects + 1):
			sections = coff.CoffSectionHeader(data[curoff:])
			sys.stdout.write('[%s].[%d] %s\n'%(v,i,sections))
			curoff += sections.get_size()
	sys.exit(0)
	return

def symbols_handler(args,parser):
	set_logging_level(args)
	for v in args.subnargs:
		cffmt = coff.Coff(v)
		for seckey in cffmt.symtables.keys():
			idx = 0
			secint = int(seckey) - 1
			section = cffmt.sections[secint]
			sys.stdout.write('[%s] %s value\n'%(seckey,section))
			for sym in cffmt.symtables[seckey]['value']:
				sys.stdout.write('    [%d] %s\n'%(idx,sym))
				idx += 1
			idx = 0
			sys.stdout.write('[%s] %s name\n'%(seckey, section))
			for sym in cffmt.symtables[seckey]['name']:
				sys.stdout.write('    [%d] %s\n'%(idx,sym))
				idx += 1
	sys.exit(0)
	return

def relocs_handler(args,parser):
	set_logging_level(args)
	for v in args.subnargs:
		cffmt = coff.Coff(v)
		idx = 0
		for seckey in cffmt.relocs.keys():
			secint = int(seckey) - 1
			section = cffmt.sections[secint]
			relocs = cffmt.relocs[seckey]
			idx = 0
			sys.stdout.write('[%s].[%s]%s relocs\n'%(v,seckey,section))
			for rel in relocs:
				sys.stdout.write('    [%d] %s\n'%(idx,rel))
				idx += 1
	sys.exit(0)
	return

def main():
	commandline='''
	{
		"verbose|v" : "+",
		"header<header_handler>" : {
			"$" : "+"
		},
		"optheader<optheader_handler>" : {
			"$" : "+"
		},
		"sections<sections_handler>" : {
			"$" : "+"
		},
		"symbols<symbols_handler>" : {
			"$" : "+"
		},
		"relocs<relocs_handler>" : {
			"$" : "+"
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
