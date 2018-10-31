#! /usr/bin/env python

import logging
import os
import struct
import sys
import datetime

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
    def __init__(self,data):
        super(CoffHeader,self).__init__()
        if len(data) < 2:
            raise Exception('len[%d] < 2'%(len(data)))
        self.__id = struct.unpack('<H',data[:2])[0]
        self.__size = 20
        self.__targetid = 0

        if len(data) < self.__size:
            raise Exception('len[%d] < %d'%(len(data),self.__size))
        self.__id,self.__numsects, self.__timestamp, self.__symtab, \
            self.__symnums, self.__optsize,self.__flags = \
                struct.unpack('<HHiiiHH',data[:self.__size])
        return

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

    def foramt_time(self,timestamp):
        tm = datetime.datetime.fromtimestamp(timestamp)
        return str(tm)


    def get_size(self):
        return self.__size

    def __str__(self):
        return 'CoffHeader(id[0x%x];numsects[0x%x];timestamp[0x%x(%s)];symtab[0x%x];symnums[0x%x];optsize[0x%x];flags[0x%x(%s)];targetid[0x%x(%s)])'%(\
                self.id,self.numsects,self.timestamp,self.foramt_time(self.timestamp),self.symtab,self.symnums,self.optsize,self.flags, self.format_flag(self.flags),self.targetid,\
                self.format_targetid(self.targetid))

    def __repr__(self):
        return str(self)


class CoffOptHeader(_LoggerObject):
    keywords = ['magic','version','szexe','szdata','szbss','entry','startex','startdata']
    headersize = 28
    def __init__(self,data):
        super(CoffOptHeader,self).__init__()
        if len(data) < self.__class__.headersize:
            raise Exception('len[%d] < [%d]'%(len(data), self.__class__.headersize))
        self.__magic, self.__version, self.__szexe, self.__szdata,self.__szbss ,\
        self.__entry, self.__startex, self.__startdata = struct.unpack('<hhllllll',data[:self.__class__.headersize])
        return

    def get_size(self):
        return self.__class__.headersize

    def __str__(self):
        return 'CoffOptHeader(magic[0x%x];version[0x%x];sizeex[0x%x];sizedata[0x%x];sizebss[0x%x];entry[0x%x];startex[0x%x];startdata[0x%x])'%(\
                self.magic,self.version,self.szexe,self.szdata,self.szbss,self.entry,self.startex, self.startdata)

    def __repr__(self):
        return str(self)


COFF_STYP_REG=0x0
COFF_STYP_DSECT=0x1
COFF_STYP_NOLOAD=0x2
COFF_STYP_GROUP=0x4
COFF_STYP_PAD=0x8
COFF_STYP_COPY=0x10
COFF_STYP_TEXT=0X20
COFF_STYP_DATA=0x40
COFF_STYP_BSS=0x80
COFF_STYP_BLOCK=0x1000
COFF_STYP_PASS=0x2000
COFF_STYP_CLINK=0x4000
COFF_STYP_VECTOR=0x8000
COFF_STYP_PADDED=0x10000


class CoffSectionHeader(_LoggerObject):
    keywords=['name','paddr','vaddr','size','offdata','offrel','reserve','numrels','lineentries','flags','reserve2','pagenum']
    headersize = 40
    def __init__(self,data):
        super(CoffSectionHeader,self).__init__()
        if len(data) < self.__class__.headersize:
            raise Exception('len[%d] < [%d]'%(len(data), self.__class__.headersize))
        self.__paddr, self.__vaddr, self.__size,self.__offdata ,\
        self.__offrel,  self.__numrels, self.__lineentries, self.__flags =\
             struct.unpack('<lllllLLL',data[8:self.__class__.headersize])
        name = data[:8]
        if sys.version[0] == '3':
            nname = b''
        else:
            nname = ''
        for b in name:
            if b == b'\x00' or b == b'\x20':
                break
            if sys.version[0] == '3':
                #logging.info('b [0x%x]'%(b))
                nname += b.to_bytes(1,'little')
            else:
                nname += b
        if sys.version[0] == '3':
            self.__name = nname.decode('utf8')
        else:
            self.__name = str(nname)
        return


    def format_flags(self,flags):
        rets = ''
        if flags & COFF_STYP_REG:
            rets = coff_add_name(rets,'REG')
        if flags & COFF_STYP_DSECT:
            rets = coff_add_name(rets,'DSECT')
        if flags & COFF_STYP_NOLOAD:
            rets = coff_add_name(rets,'NOLOAD')            
        if flags & COFF_STYP_GROUP:
            rets = coff_add_name(rets,'GROUP')
        if flags & COFF_STYP_PAD:
            rets = coff_add_name(rets,'PAD')
        if flags & COFF_STYP_COPY:
            rets = coff_add_name(rets,'COPY')
        if flags & COFF_STYP_TEXT:
            rets = coff_add_name(rets,'TEXT')
        if flags & COFF_STYP_DATA:
            rets = coff_add_name(rets,'DATA')
        if flags & COFF_STYP_BSS:
            rets = coff_add_name(rets,'BSS')
        if flags & COFF_STYP_BLOCK:
            rets = coff_add_name(rets,'BLOCK')
        if flags & COFF_STYP_PASS:
            rets = coff_add_name(rets,'PASS')
        if flags & COFF_STYP_CLINK:
            rets = coff_add_name(rets,'CLINK')
        if flags & COFF_STYP_VECTOR:
            rets = coff_add_name(rets,'VECTOR')
        if flags & COFF_STYP_PADDED:
            rets = coff_add_name(rets,'PADDED')
        return rets

    def get_size(self):
        return self.__class__.headersize

    def __str__(self):
        return 'CoffSectionHeader(name[%s];paddr[0x%x];vaddr[0x%x];size[0x%x];offdata[0x%x];offrel[0x%x];numrels[0x%x];lineentries[0x%x];flags[0x%x(%s)])'%(\
                self.name,self.paddr,self.vaddr,self.size,self.offdata,self.offrel,self.numrels , self.lineentries,self.flags, self.format_flags(self.flags))

    def __repr__(self):
        return str(self)


class CoffSymtable(_LoggerObject):
    keywords = ['name','value','sectnum','type','storagecls','numaux']
    headersize = 18
    def __init__(self,data,symoff,stroff,strend):
        super(CoffSymtable,self).__init__()
        name = data[symoff:(symoff + 8)]
        self.__value, self.__sectnum,self.__type, self.__storagecls,self.__numaux = \
            struct.unpack('<lhHBB', data[(symoff+8):(symoff + self.__class__.headersize)])
        self.__size = self.__class__.headersize
        ni = 0
        for b in name:
            if b == b'\x00':
                break
            ni += 1
        if ni > 0:
            if sys.version[0] == '3':
                nname = b''
            else:
                nname = ''
            for b in name:
                if b == b'\x00' or b == b'\x20':
                    break
                if sys.version[0] == '3':
                    #logging.info('b [0x%x]'%(b))
                    nname += b.to_bytes(1,'little')
                else:
                    nname += b
            if sys.version[0] == '3':
                self.__name = nname.decode('utf8')
            else:
                self.__name = str(nname)
        else:
            # this means we get from the stroff
            nameoff = struct.unpack('<l',data[(symoff + 4):(symoff + 8)])[0]
            nameoff += stroff
            if sys.version[0] == '3':
                nname = b''
            else:
                nname = ''
            while nameoff < strend:
                b = data[nameoff]
                if b == b'\x00':
                    break
                if sys.version[0] == '3':
                    #logging.info('b [0x%x]'%(b))
                    nname += b.to_bytes(1,'little')
                else:
                    nname += b
                nameoff += 1
            if sys.version[0] == '3':
                self.__name = nname.decode('utf8')
            else:
                self.__name = str(nname)
        if self.__numaux > 0 :
            self.__size += self.__numaux * self.__class__.headersize
        return



    def __str__(self):
        rets = '[%s] '%(self.name)
        rets += 'value[0x%x]'%(self.value)
        rets += 'sectnum[%d]'%(self.sectnum)
        rets += 'type[0x%x]'%(self.type)
        rets += 'storagecls[0x%x]'%(self.storagecls)
        rets += 'numaux[%d]'%(self.numaux)
        return rets

    def __repr__(self):
        return str(self)

    def get_size(self):
        return self.__size


class Coff(_LoggerObject):
    keywords = ['fname','header','opthdr','sections','symtables']    
    def __read_binary(self,infile=None):
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

    def __reset(self):
        self.__fname = None
        self.__header = None
        self.__opthdr = None
        self.__sections = []
        self.__symtables = []
        self.__stroffset = -1
        self.__symoffset = -1
        self.__strsize = -1
        return

    def __parse_symtable(self,data):
        symoff = self.__symoffset
        i = 0
        while i < self.__header.symnums:
            sym = CoffSymtable(data,symoff, self.__stroffset, (self.__stroffset + self.__strsize))
            self.__symtables.append(sym)
            i += 1
            i += sym.numaux
            symoff += sym.get_size()
        return


    def __parse_coff(self,data):
        self.__header = CoffHeader(data)
        cursize = self.__header.get_size()
        self.__opthdr = None
        if self.__header.optsize > 0:
            self.__opthdr = CoffOptHeader(data[cursize:])
            cursize += self.__opthdr.get_size()
        # now to get the numsections
        for i in range(self.__header.numsects):
            section = CoffSectionHeader(data[cursize:])
            self.__sections.append(section)
            cursize += section.get_size()
        self.__symoffset = self.__header.symtab
        self.__stroffset = self.__header.symtab + (self.__header.symnums * CoffSymtable.headersize)
        self.__strsize = struct.unpack('<I',data[self.__stroffset:(self.__stroffset+4)])[0]
        self.__parse_symtable(data)
        return

    def __init__(self,fname=None):
        super(Coff,self).__init__()
        self.__reset()
        self.__fname = fname
        data = self.__read_binary(fname)
        self.__parse_coff(data)
        return

    def __str__(self):
        return '[%s] %s'%(self.fname,self.header)

    def __repr__(self):
        return str(self)


