#! /usr/bin/env python

import logging
import os
import struct


class _LoggerObject(object):
    def __init__(self,cmdname='coff'):
        self.__logger = logging.getLogger(cmdname)
        if len(self.__logger.handlers) == 0:
            loglvl = logging.WARN
            lvlname = '%s_LOGLEVEL'%(cmdname)
            lvlname = lvlname.upper()
            if lvlname in os.environ.keys():
                v = os.environ[lvlname]
                vint = 0
                try:
                    vint = int(v)
                except:
                    vint = 0
                if vint >= 4:
                    loglvl = logging.DEBUG
                elif vint >= 3:
                    loglvl = logging.INFO
            handler = logging.StreamHandler()
            fmt = "%(levelname)-8s %(message)s"
            fmtname = '%s_LOGFMT'%(cmdname)
            fmtname = fmtname.upper()
            if fmtname in os.environ.keys():
                v = os.environ[fmtname]
                if v is not None and len(v) > 0:
                    fmt = v
            formatter = logging.Formatter(fmt)
            handler.setFormatter(formatter)
            self.__logger.addHandler(handler)
            self.__logger.setLevel(loglvl)
            # we do not want any more output debug
            self.__logger.propagate = False

    def format_string(self,arr):
        s = ''
        if isinstance(arr,list):
            i = 0
            for c in arr:
                s += '[%d]%s\n'%(i,c)
                i += 1
        elif isinstance(arr,dict):
            for c in arr.keys():
                s += '%s=%s\n'%(c,arr[c])
        else:
            s += '%s'%(arr)
        return s

    def format_call_msg(self,msg,callstack):
        inmsg = ''  
        if callstack is not None:
            try:
                frame = sys._getframe(callstack)
                inmsg += '[%-10s:%-20s:%-5s] '%(frame.f_code.co_filename,frame.f_code.co_name,frame.f_lineno)
            except:
                inmsg = ''
        inmsg += msg
        return inmsg

    def info(self,msg,callstack=1):
        inmsg = msg
        if callstack is not None:
            inmsg = self.format_call_msg(msg,(callstack + 1))
        return self.__logger.info('%s'%(inmsg))

    def error(self,msg,callstack=1):
        inmsg = msg
        if callstack is not None:
            inmsg = self.format_call_msg(msg,(callstack + 1))
        return self.__logger.error('%s'%(inmsg))

    def warn(self,msg,callstack=1):
        inmsg = msg
        if callstack is not None:
            inmsg = self.format_call_msg(msg,(callstack + 1))
        return self.__logger.warn('%s'%(inmsg))

    def debug(self,msg,callstack=1):
        inmsg = msg
        if callstack is not None:
            inmsg = self.format_call_msg(msg,(callstack + 1))
        return self.__logger.debug('%s'%(inmsg))

    def fatal(self,msg,callstack=1):
        inmsg = msg
        if callstack is not None:
            inmsg = self.format_call_msg(msg,(callstack + 1))
        return self.__logger.fatal('%s'%(inmsg))

COFF_F_RELFLG=1
COFF_F_EXEC=2
COFF_F_LNNO=4
COFF_F_LSYMS=8
COFF_F_LITTLE=0x100
COFF_F_BIG=0x200
COFF_F_SYMMERGE=0x1000


def coff_add_name(s,items):
	rets = s
	if len(rets) > 0:
		rets += ';'
	rets += items
	return rets

class CoffHeader(_LoggerObject):
	keywords = ['id','numsects','timestamp','symtab','symnums','optsize','flags','targetid']
	headersize = 22
	def __init__(self,data):
		super(CoffHeader,self).__init__()
		if len(data) < self.__class__.headersize:
			raise Exception('len[%d] < %d'%(len(data),self.__class__.headersize))
		self.__id,self.__numsects, self.__timestamp, self.__symtab, \
			self.__symnums, self.__optsize,self.__flags,self.__targetid = \
			struct.unpack('<HHiiiHHH',data[:self.__class__.headersize])
		return


	def format_flag(self,flag):
		rets = ''
		if flag & COFF_F_RELFLG:
			rets = coff_add_name(rets,'REL')
		if flag & COFF_F_EXEC:
			rets = coff_add_name(rets,'EXEC')
		if flag & COFF_F_LNNO:
			rets = coff_add_name(rets,'LNNO')
		if flag & COFF_F_LSYMS:
			rets = coff_add_name(rets,'LSYMS')
		if flag & COFF_F_LITTLE:
			rets = coff_add_name(rets,'LITTLE')
		if flag & COFF_F_BIG:
			rets = coff_add_name(rets,'BIG')
		if flag & COFF_F_SYMMERGE:
			rets = coff_add_name(rets,'SYMMERGE')
		return rets

	def format_targetid(self,targetid):
		rets = ''
		if targetid == 0x97:
			rets = 'TMS470'
		elif targetid == 0x98:
			rets = 'TMS320C5400'
		elif targetid == 0x99:
			rets = 'TMS320C6000'
		elif targetid == 0x9c:
			rets = 'TMS320C5500'
		elif targetid == 0x9d:
			rets = 'TMS320C2800'
		elif targetid == 0xa0:
			rets = 'MSP430'
		elif targetid == 0xa1:
			rets = 'TMS320C5500+'
		return rets


	def __getattr__(self,k):
		nk = k
		if k in self.__class__.keywords:
			nk = '_%s__%s'%(self.__class__.__name__,k)
		if nk in self.__dict__.keys():
			return self.__dict__[nk]
		return None

	def __setattr__(self,k,v):
		if k in self.__class__.keywords:
			raise Exception('can not set [%s]'%(k))
		self.__dict__[k] = v
		return

	def get_size(self):
		return self.__class__.headersize

	def __str__(self):
		return 'CoffHeader(id[0x%x];numsects[0x%x];timestamp[0x%x];symtab[0x%x];symnums[0x%x];optsize[0x%x];flags[0x%x(%s)];targetid[0x%x(%s)])'%(\
				self.id,self.numsects,self.timestamp,self.symtab,self.symnums,self.optsize,self.flags, self.format_flag(self.flags),self.targetid,\
				self.format_targetid(self.targetid))

	def __repr__(self):
		return str(self)


class CoffOptHeader(_LoggerObject):
	keywords = ['magic','version','szexe','szdata','szbss','entry','startex','startdata']
	headersize = 28
	def __init__(self,data):
		if len(data) < self.__class__.headersize:
			raise Exception('len[%d] < [%d]'%(len(data), self.__class__.headersize))
		self.__magic, self.__version, self.__szexe, self.__szdata,self.__szbss ,\
		self.__entry, self.__startex, self.__startdata = struct.unpack('<hhllllll',data[:self.__class__.headersize])
		return

	def __getattr__(self,k):
		nk = k
		if k in self.__class__.keywords:
			nk = '_%s__%s'%(self.__class__.__name__,k)
		if nk in self.__dict__.keys():
			return self.__dict__[nk]
		return None

	def __setattr__(self,k,v):
		if k in self.__class__.keywords:
			raise Exception('can not set [%s]'%(k))
		self.__dict__[k] = v
		return

	def get_size(self):
		return self.__class__.headersize

	def __str__(self):
		return 'CoffOptHeader(magic[0x%x];version[0x%x];sizeex[0x%x];sizedata[0x%x];sizebss[0x%x];entry[0x%x];startex[0x%x];startdata[0x%x])'%(\
				self.magic,self.version,self.szexe,self.szdata,self.szbss,self.entry,self.startex, self.startdata)

	def __repr__(self):
		return str(self)


class CoffSectionHeader(_LoggerObject):
	keywords=['name','paddr','vaddr','size','offdata','offrel','reserve','numrels','lineentries','flags','reserve2','pagenum']
	headersize = 48
	def __init__(self,data):
		if len(data) < self.__class__.headersize:
			raise Exception('len[%d] < [%d]'%(len(data), self.__class__.headersize))
		name, self.__paddr, self.__vaddr, self.__size,self.__offdata ,\
		self.__offrel, self.__reserve, self.__numrels, self.__lineentries, self.__flags ,\
		self.__reserve2, self.__pagenum = struct.unpack('<s8llllllLLLHH',data[:self.__class__.headersize])				
		nname = b''
		for b in name:
			if b == b'\x0':
				break
			nname += b
		if sys.version[0] == '3':
			self.__name = name.decode('utf8')
		else:
			self.__name = str(name)
		return

	def __getattr__(self,k):
		nk = k
		if k in self.__class__.keywords:
			nk = '_%s__%s'%(self.__class__.__name__,k)
		if nk in self.__dict__.keys():
			return self.__dict__[nk]
		return None

	def __setattr__(self,k,v):
		if k in self.__class__.keywords:
			raise Exception('can not set [%s]'%(k))
		self.__dict__[k] = v
		return

	def get_size(self):
		return self.__class__.headersize

	def __str__(self):
		return 'CoffSectionHeader(name[%s];paddr[0x%x];vaddr[0x%x];size[0x%x];offdata[0x%x];offrel[0x%x];reserve[0x%x];numrels[0x%x]lineentries[0x%x]flags[0x%x]reserve2[0x%x]pagenum[0x%x])'%(\
				self.name,self.paddr,self.vaddr,self.size,self.offdata,self.offrel,self.reserve, self.numrels , \
				self.lineentries,self.flags,self.reserve2,self.pagenum)

	def __repr__(self):
		return str(self)
