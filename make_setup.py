#! /usr/bin/python

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
import logging
import re

def release_setup_file(verfile,verpat,setuptmpl=None,setupfile=None):
	vernum = '0.0.1'
	with open(verfile,'r') as f:
		for l in f:
			l = l.rstrip('\r\n')
			vernum = '\'%s\''%(l)
			break
	fin = sys.stdin
	fout = sys.stdout
	if setuptmpl is not None:
		fin = open(setuptmpl,'r')

	if setupfile is not None:
		fout = open(setupfile,'w+')
	for l in fin:
		l = l.rstrip('\r\n')
		l = re.sub(verpat,vernum,l)
		fout.write('%s\n'%(l))

	if fout != sys.stdout:
		fout.close()
	fout = None
	if fin != sys.stdin:
		fin.close()
	fin = None
	return

def main():
	script_dir = os.path.abspath(os.path.dirname(__file__))
	verfile = os.path.join(script_dir,'VERSION')
	verpat = r'%VERSIONNUM%'
	setuptmpl = os.path.join(script_dir,'setup.py.tmpl')
	setupfile = os.path.join(script_dir,'setup.py')
	release_setup_file(verfile,verpat,setuptmpl,setupfile)
	return

if __name__ == '__main__':
	main()

