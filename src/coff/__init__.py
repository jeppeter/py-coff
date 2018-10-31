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


class CoffHeader(_LoggerObject):
	keywords = ['id','numsects','timestamp','symtab','symnums','optsize','flags','targetid']
	headersize = 22
	def __init__(self,data):
		super(CoffHeader,self).__init__()
		if len(data) < self.__class__.headersize:
			raise Exception('len[%d] < %d'%(len(data),self.__class__.headersize))
		self.__id,self.__numsects, self.__timestamp, self.__symtab, \
			self.__symnums, self.__optsize,self.__flags,self.__targetid = \
			struct.unpack('<HHIIIHHH',data[:self.__class__.headersize])
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
		return 'CoffHeader(id[0x%x];numsects[0x%x];timestamp[0x%x];symtab[0x%x];symnums[0x%x];optsize[0x%x];flags[0x%x];targetid[0x%x])'%(\
				self.id,self.numsects,self.timestamp,self.symtab,self.symnums,self.optsize,self.flags,self.targetid)

	def __repr__(self):
		return str(self)