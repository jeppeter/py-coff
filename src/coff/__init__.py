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

    def __eq__(self,other):
        for v in self.__class__.keywords:
            sv = self.__getattr__(v)
            ov = self.__getattr__(v)
            if sv != ov:
                return False
        return True


IMAGE_FILE_RELOCS_STRIPPED=1
IMAGE_FILE_EXECUTABLE_IMAGE=2
IMAGE_FILE_LINE_NUMS_STRIPPED=4
IMAGE_FILE_LOCAL_SYMS_STRIPPED=8
IMAGE_FILE_AGGRESSIVE_WS_TRIM=0x10
IMAGE_FILE_LARGE_ADDRESS_AWARE=0x20
IMAGE_FILE_BYTES_REVERSED_LO=0x80
IMAGE_FILE_32BIT_MACHINE=0x100
IMAGE_FILE_DEBUG_STRIPPED=0x200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x400
IMAGE_FILE_NET_RUN_FROM_SWAP=0x800
IMAGE_FILE_SYSTEM=0x1000
IMAGE_FILE_DLL=0x2000
IMAGE_FILE_UP_SYSTEM_ONLY=0x4000
IMAGE_FILE_BYTES_REVERSED_HI=0x8000


def coff_add_name(s,items):
    rets = s
    if len(rets) > 0:
        rets += ';'
    rets += items
    return rets

class CoffHeader(_LoggerObject):
    keywords = ['id','numsects','timestamp','symtab','symnums','optsize','flags']
    headersize = 20
    def __init__(self,data):
        super(CoffHeader,self).__init__()
        if len(data) < 2:
            raise Exception('len[%d] < 2'%(len(data)))
        self.__id = struct.unpack('<H',data[:2])[0]
        self.__size = 20

        if len(data) < self.__size:
            raise Exception('len[%d] < %d'%(len(data),self.__size))
        self.__id,self.__numsects, self.__timestamp, self.__symtab, \
            self.__symnums, self.__optsize,self.__flags = \
                struct.unpack('<HHiiiHH',data[:self.__size])
        return

    def format_id(self,tid):
        rets = ''
        if tid == 0x8664:
            rets = 'amd64'
        elif tid == 0x14c:
            rets = 'i386'
        return rets


    def format_flag(self,flag):
        rets = ''
        if flag & IMAGE_FILE_RELOCS_STRIPPED:
            rets = coff_add_name(rets,'relocs_stripped')
        elif flag & IMAGE_FILE_EXECUTABLE_IMAGE:
            rets = coff_add_name(rets,'executable')
        elif flag & IMAGE_FILE_LINE_NUMS_STRIPPED:
            rets = coff_add_name(rets,'LINE_NUMS_STRIPPED')
        elif flag & IMAGE_FILE_LOCAL_SYMS_STRIPPED:
            rets = coff_add_name(rets,'LOCAL_SYMS_STRIPPED')
        elif flag & IMAGE_FILE_AGGRESSIVE_WS_TRIM:
            rets = coff_add_name(rets,'AGGRESSIVE_WS_TRIM')
        elif flag & IMAGE_FILE_LARGE_ADDRESS_AWARE:
            rets = coff_add_name(rets,'LARGE_ADDRESS_WARE')
        elif flag & IMAGE_FILE_BYTES_REVERSED_LO:
            rets = coff_add_name(rets,'BYTES_RESERVED_LO')
        elif flag & IMAGE_FILE_32BIT_MACHINE:
            rets = coff_add_name(rets,'32BIT_MACHINE')
        elif flag & IMAGE_FILE_DEBUG_STRIPPED:
            rets = coff_add_name(rets,'DEBUG_STRIPPED')
        elif flag & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:
            rets = coff_add_name(rets,'REMOVABLE_RUN_FROM_SWAP')
        elif flag & IMAGE_FILE_NET_RUN_FROM_SWAP:
            rets = coff_add_name(rets,'NET_RUN_FROM_SWAP')
        elif flag & IMAGE_FILE_SYSTEM:
            rets = coff_add_name(rets,'SYSTEM')
        elif flag & IMAGE_FILE_DLL:
            rets = coff_add_name(rets,'DLL')
        elif flag & IMAGE_FILE_UP_SYSTEM_ONLY:
            rets = coff_add_name(rets,'UP_SYSTEM_ONLY')
        elif flag & IMAGE_FILE_BYTES_REVERSED_HI:
            rets = coff_add_name(rets,'BYTES_RESERVED_HI')
        return rets

    def foramt_time(self,timestamp):
        tm = datetime.datetime.fromtimestamp(timestamp)
        return str(tm)


    def get_size(self):
        return self.__size

    def __str__(self):
        return 'CoffHeader(id[0x%x(%s)];numsects[0x%x];timestamp[0x%x(%s)];symtab[0x%x];symnums[0x%x];optsize[0x%x];flags[0x%x(%s)];)'%(\
                self.id,self.format_id(self.id),self.numsects,self.timestamp,self.foramt_time(self.timestamp),self.symtab,self.symnums,self.optsize,self.flags, self.format_flag(self.flags))

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


IMAGE_SCN_TYPE_NO_PAD=0x8
IMAGE_SCN_CNT_CODE=0X20
IMAGE_SCN_CNT_INITIALIZED_DATA=0x40
IMAGE_SCN_CNT_UNINITIALIZED_DATA=0x80
IMAGE_SCN_LNK_OTHER=0x100
IMAGE_SCN_LNK_INFO=0x200
IMAGE_SCN_LNK_REMOVE=0x800
IMAGE_SCN_LNK_COMDAT=0x1000
IMAGE_SCN_GPREL=0x8000
IMAGE_SCN_ALIGN_1BYTES=0x100000
IMAGE_SCN_ALIGN_2BYTES=0x200000
IMAGE_SCN_ALIGN_4BYTES=0x300000
IMAGE_SCN_ALIGN_8BYTES=0x400000
IMAGE_SCN_ALIGN_16BYTES=0x500000
IMAGE_SCN_ALIGN_32BYTES=0x600000
IMAGE_SCN_ALIGN_64BYTES=0x700000
IMAGE_SCN_ALIGN_128BYTES=0x80000
IMAGE_SCN_ALIGN_256BYTES=0x900000
IMAGE_SCN_ALIGN_512BYTES=0xa00000
IMAGE_SCN_ALIGN_1024BYTES=0xb00000
IMAGE_SCN_ALIGN_2048BYTES=0xc00000
IMAGE_SCN_ALIGN_4096BYTES=0xd00000
IMAGE_SCN_ALIGN_8192BYTES=0xe00000
IMAGE_SCN_ALIGN_MASK=0xf00000
IMAGE_SCN_LNK_NRELOC_OVFL=0x1000000
IMAGE_SCN_MEM_DISCARDABLE=0x2000000
IMAGE_SCN_MEM_NOT_CACHED=0x4000000
IMAGE_SCN_MEM_NOT_PAGED=0x8000000
IMAGE_SCN_MEM_SHARED=0x10000000
IMAGE_SCN_MEM_EXECUTE=0x20000000
IMAGE_SCN_MEM_READ=0x40000000
IMAGE_SCN_MEM_WRITE=0x80000000


class CoffSectionHeader(_LoggerObject):
    keywords=['name','paddr','vaddr','size','offdata','offrel','numrels','numlnno','lineentries','flags']
    headersize = 40
    def __init__(self,data):
        super(CoffSectionHeader,self).__init__()
        if len(data) < self.__class__.headersize:
            raise Exception('len[%d] < [%d]'%(len(data), self.__class__.headersize))
        self.__paddr, self.__vaddr, self.__size,self.__offdata ,\
        self.__offrel, self.__lineentries, self.__numrels, self.__numlnno ,self.__flags =\
             struct.unpack('<llllllHHl',data[8:self.__class__.headersize])
        name = data[:8]
        if sys.version[0] == '3':
            nname = b''
        else:
            nname = ''
        for b in name:
            if sys.version[0] == '3':
                if b == 0 or b == 0x20:
                    break
            else:
                if ord(b) == 0 or ord(b) == 0x20:
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
        if flags & IMAGE_SCN_TYPE_NO_PAD:
            rets = coff_add_name(rets,'NO_PAD')
        if flags & IMAGE_SCN_CNT_CODE:
            rets = coff_add_name(rets,'CODE')
        if flags & IMAGE_SCN_CNT_INITIALIZED_DATA:
            rets = coff_add_name(rets,'DATA')            
        if flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            rets = coff_add_name(rets,'BSS')
        if flags & IMAGE_SCN_LNK_OTHER:
            rets = coff_add_name(rets,'OTHER')
        if flags & IMAGE_SCN_LNK_INFO:
            rets = coff_add_name(rets,'INFO')
        if flags & IMAGE_SCN_LNK_REMOVE:
            rets = coff_add_name(rets,'REMOVE')
        if flags & IMAGE_SCN_LNK_COMDAT:
            rets = coff_add_name(rets,'COMDAT')
        if flags & IMAGE_SCN_GPREL:
            rets = coff_add_name(rets,'GPREL')
        alignmask = flags & IMAGE_SCN_ALIGN_MASK
        if alignmask == IMAGE_SCN_ALIGN_1BYTES:
            rets = coff_add_name(rets,'1 byte align')
        elif alignmask == IMAGE_SCN_ALIGN_2BYTES:
            rets = coff_add_name(rets,'2 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_4BYTES:
            rets = coff_add_name(rets,'4 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_8BYTES:
            rets = coff_add_name(rets,'8 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_16BYTES:
            rets = coff_add_name(rets,'16 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_32BYTES:
            rets = coff_add_name(rets,'32 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_64BYTES:
            rets = coff_add_name(rets,'64 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_128BYTES:
            rets = coff_add_name(rets,'128 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_256BYTES:
            rets = coff_add_name(rets,'256 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_512BYTES:
            rets = coff_add_name(rets,'512 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_1024BYTES:
            rets = coff_add_name(rets,'1024 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_2048BYTES:
            rets = coff_add_name(rets,'2048 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_4096BYTES:
            rets = coff_add_name(rets,'4096 bytes align')
        elif alignmask == IMAGE_SCN_ALIGN_8192BYTES:
            rets = coff_add_name(rets,'8192 bytes align')

        if flags & IMAGE_SCN_LNK_NRELOC_OVFL:
            rets = coff_add_name(rets,'OVFL')
        if flags & IMAGE_SCN_MEM_DISCARDABLE:
            rets = coff_add_name(rets,'DISCARDABLE')

        if flags & IMAGE_SCN_MEM_NOT_CACHED:
            rets = coff_add_name(rets,'NOT_CACHED')

        if flags & IMAGE_SCN_MEM_NOT_PAGED:
            rets = coff_add_name(rets,'NOT_PAGED')
        if flags & IMAGE_SCN_MEM_SHARED:
            rets = coff_add_name(rets,'MEM_SHARED')

        if flags & IMAGE_SCN_MEM_EXECUTE:
            rets = coff_add_name(rets,'EXECUTE')
        if flags & IMAGE_SCN_MEM_READ:
            rets = coff_add_name(rets,'READ')
        if flags & IMAGE_SCN_MEM_WRITE:
            rets = coff_add_name(rets,'WRITE')
        return rets

    def get_size(self):
        return self.__class__.headersize

    def __str__(self):
        return 'CoffSectionHeader(name[%s];paddr[0x%x];vaddr[0x%x];size[0x%x];offdata[0x%x];offrel[0x%x];numrels[0x%x];lineentries[0x%x];numlnno[0x%x];flags[0x%x(%s)])'%(\
                self.name,self.paddr,self.vaddr,self.size,self.offdata,self.offrel,self.numrels , self.lineentries, self.numlnno,self.flags, self.format_flags(self.flags))

    def __repr__(self):
        return str(self)

IMAGE_SYM_CLASS_END_OF_FUNCTION=0xff
IMAGE_SYM_CLASS_NULL=0x0
IMAGE_SYM_CLASS_AUTOMATIC=0x1
IMAGE_SYM_CLASS_EXTERNAL=0x2
IMAGE_SYM_CLASS_STATIC=0x3
IMAGE_SYM_CLASS_REGISTER=0x4
IMAGE_SYM_CLASS_EXTERNAL_DEF=0x5
IMAGE_SYM_CLASS_LABEL=0x6
IMAGE_SYM_CLASS_UNDEFINED_LABEL=0x7
IMAGE_SYM_CLASS_MEMBER_OF_STRUCT=0x8
IMAGE_SYM_CLASS_ARGUMENT=0x9
IMAGE_SYM_CLASS_STRUCT_TAG=0xa
IMAGE_SYM_CLASS_MEMBER_OF_UNION=0xb
IMAGE_SYM_CLASS_UNION_TAG=0xc
IMAGE_SYM_CLASS_TYPE_DEFINITION=0xd
IMAGE_SYM_CLASS_UNDEFINED_STATIC=0xe
IMAGE_SYM_CLASS_ENUM_TAG=0xf
IMAGE_SYM_CLASS_MEMBER_OF_ENUM=0x10
IMAGE_SYM_CLASS_REGISTER_PARAM=0x11
IMAGE_SYM_CLASS_BIT_FIELD=0x12
IMAGE_SYM_CLASS_BLOCK=0x64
IMAGE_SYM_CLASS_FUNCTION=0x65
IMAGE_SYM_CLASS_END_OF_STRUCT=0x66
IMAGE_SYM_CLASS_FILE=0x67
IMAGE_SYM_CLASS_SECTION=0x68
IMAGE_SYM_CLASS_WEAK_EXTERNAL=0x69
IMAGE_SYM_CLASS_CLR_TOKEN=0x6b

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
            if sys.version[0] == '3':
                if b == 0:
                    break
            else:
                if ord(b) == 0:
                    break
            ni += 1
        if ni > 0:
            if sys.version[0] == '3':
                nname = b''
            else:
                nname = ''
            for b in name:
                if sys.version[0] == '3':
                    if b == 0 or b == 0x20:
                        break
                else:
                    if ord(b) == 0 or ord(b) == 0x20:
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
                if sys.version[0] == '3':
                    if b == 0x0:
                        break
                else:
                    if ord(b) == 0:
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
        self.size = 0
        return

    def format_storagecls(self,storagecls):
        rets= ''
        if storagecls == IMAGE_SYM_CLASS_END_OF_FUNCTION:
            rets = 'END_OF_FUNCTION'
        elif storagecls == IMAGE_SYM_CLASS_NULL:
            rets = 'NULL'
        elif storagecls == IMAGE_SYM_CLASS_AUTOMATIC:
            rets = 'ATOMIC'
        elif storagecls == IMAGE_SYM_CLASS_EXTERNAL:
            rets = 'EXTERNAL'
        elif storagecls == IMAGE_SYM_CLASS_STATIC:
            rets = 'STATIC'
        elif storagecls == IMAGE_SYM_CLASS_REGISTER:
            rets = 'REGISTER'
        elif storagecls == IMAGE_SYM_CLASS_EXTERNAL_DEF:
            rets = 'EXTERNAL_DEF'
        elif storagecls == IMAGE_SYM_CLASS_LABEL:
            rets = 'LABEL'
        elif storagecls == IMAGE_SYM_CLASS_UNDEFINED_LABEL:
            rets = 'UNDEFINED_LABEL'
        elif storagecls == IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
            rets = 'MEMBER_OF_STRUCT'
        elif storagecls == IMAGE_SYM_CLASS_ARGUMENT:
            rets = 'ARGUMENT'
        elif storagecls == IMAGE_SYM_CLASS_STRUCT_TAG:
            rets = 'STRUCT_TAG'
        elif storagecls == IMAGE_SYM_CLASS_MEMBER_OF_UNION:
            rets = 'MEMBER_OF_UNION'
        elif storagecls == IMAGE_SYM_CLASS_UNION_TAG:
            rets = 'UNION_TAG'
        elif storagecls == IMAGE_SYM_CLASS_TYPE_DEFINITION:
            rets = 'TYPE_DEFINITION'
        elif storagecls == IMAGE_SYM_CLASS_UNDEFINED_STATIC:
            rets = 'UNDEFINED_STATIC'
        elif storagecls == IMAGE_SYM_CLASS_ENUM_TAG:
            rets = 'ENUM_TAG'
        elif storagecls == IMAGE_SYM_CLASS_MEMBER_OF_ENUM:
            rets = 'MEMBER_OF_ENUM'
        elif storagecls == IMAGE_SYM_CLASS_REGISTER_PARAM:
            rets = 'REGISTER_PARAM'
        elif storagecls == IMAGE_SYM_CLASS_BIT_FIELD:
            rets = 'BIT_FIELD'
        elif storagecls == IMAGE_SYM_CLASS_BLOCK:
            rets = 'BLOCK'
        elif storagecls == IMAGE_SYM_CLASS_FUNCTION:
            rets = 'FUNCTION'
        elif storagecls == IMAGE_SYM_CLASS_END_OF_STRUCT:
            rets = 'END_OF_STRUCT'
        elif storagecls == IMAGE_SYM_CLASS_FILE:
            rets = 'FILE'
        elif storagecls == IMAGE_SYM_CLASS_SECTION:
            rets = 'SECTION'
        elif storagecls == IMAGE_SYM_CLASS_WEAK_EXTERNAL:
            rets = 'WEAK_EXTERNAL'
        elif storagecls == IMAGE_SYM_CLASS_CLR_TOKEN:
            rets = 'CLR_TOKEN'
        return rets


    def __str__(self):
        rets = '[%s] '%(self.name)
        rets += 'value[0x%x]'%(self.value)
        rets += 'sectnum[%d]'%(self.sectnum)
        rets += 'type[0x%x]'%(self.type)
        rets += 'storagecls[0x%x(%s)]'%(self.storagecls, self.format_storagecls(self.storagecls))
        rets += 'numaux[%d]'%(self.numaux)
        rets += 'size[0x%x]'%(self.size)
        return rets

    def __repr__(self):
        return str(self)

    def get_size(self):
        return self.__size


IMAGE_REL_AMD64_ABSOLUTE=0x0
IMAGE_REL_AMD64_ADDR64=0x1
IMAGE_REL_AMD64_ADDR32=0x2
IMAGE_REL_AMD64_ADDR32NB=0x3
IMAGE_REL_AMD64_REL32=0x4
IMAGE_REL_AMD64_REL32_1=0x5
IMAGE_REL_AMD64_REL32_2=0x6
IMAGE_REL_AMD64_REL32_3=0x7
IMAGE_REL_AMD64_REL32_4=0x8
IMAGE_REL_AMD64_REL32_5=0x9
IMAGE_REL_AMD64_SECTION=0xa
IMAGE_REL_AMD64_SECREL=0xb
IMAGE_REL_AMD64_SECREL7=0xc
IMAGE_REL_AMD64_TOKEN=0xd
IMAGE_REL_AMD64_SREL32=0xe
IMAGE_REL_AMD64_PAIR=0xf
IMAGE_REL_AMD64_SSPAN32=0x10


IMAGE_REL_I386_ABSOLUTE=0x0
IMAGE_REL_I386_DIR16=0x1
IMAGE_REL_I386_REL16=0x2
IMAGE_REL_I386_DIR32=0x6
IMAGE_REL_I386_DIR32NB=0x7
IMAGE_REL_I386_SEG12=0x9
IMAGE_REL_I386_SECTION=0xa
IMAGE_REL_I386_SECREL=0xb
IMAGE_REL_I386_TOKEN=0xc
IMAGE_REL_I386_SECREL7=0xd
IMAGE_REL_I386_REL32=0x14

class CoffReloc(_LoggerObject):
    keywords = ['name','vaddr','type']
    headersize = 10
    def __init__(self,data,dataoff,basesymoff,stroff,strend):
        if (dataoff + self.__class__.headersize) > len(data):
            raise Exception('[%d + %d] > [%d]'%(dataoff,self.__class__.headersize, len(data)))
        self.__vaddr,symidx,self.__type = struct.unpack('<LLH', data[dataoff:(dataoff+self.__class__.headersize)])
        symoff = (basesymoff + CoffSymtable.headersize * symidx)
        if (symoff + CoffSymtable.headersize) > len(data):
            raise Exception('symidx [%d] outof size'%(symidx))
        name = data[(symoff) : (symoff + 8)]
        ni = 0
        for b in name:
            if sys.version[0] == '3':
                if b == 0x0:
                    break
            else:
                if ord(b) == 0x0:
                    break
            ni += 1
        if ni > 0:
            if sys.version[0] == '3':
                nname = b''
            else:
                nname = ''
            for b in name:
                if sys.version[0] == '3':
                    if b == 0x0 or b == 0x20:
                        break
                else:
                    if ord(b) == 0x0 or ord(b) == 0x20:
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
                if sys.version[0] == '3':
                    if b == 0x0:
                        break
                else:
                    if ord(b) == 0:
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
        self.size = 0
        return

    def __str__(self):
        rets = 'CoffReloc(name[%s];vaddr[0x%x];type[0x%x];size[0x%x])'%(self.name,self.vaddr,self.type,self.size)
        return rets

    def __repr__(self):
        return str(self)

    def get_size(self):
        return self.__class__.headersize



class Coff(_LoggerObject):
    keywords = ['fname','header','opthdr','sections','relocs','symtables']
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
        self.__relocs = dict()
        self.__stroffset = -1
        self.__symoffset = -1
        self.__strsize = -1
        return

    def __parse_symtable(self,data):
        symoff = self.__symoffset
        i = 0
        self.__symtables = dict()
        while i < self.__header.symnums:
            sym = CoffSymtable(data,symoff, self.__stroffset, (self.__stroffset + self.__strsize))
            i += 1
            i += sym.numaux
            symoff += sym.get_size()
            if sym.sectnum < 1 or sym.sectnum > len(self.sections):
                logging.info('%s'%(sym))
                continue
            if sym.numaux != 0:
                logging.info('%s'%(sym))
                continue            
            section = self.sections[(sym.sectnum-1)]
            seckey = sym.sectnum - 1
            if seckey not in self.__symtables.keys():
                self.__symtables[seckey] = []
            self.__symtables[seckey].append(sym)
        for seckey in self.__symtables.keys():
            valuetble = self.__symtables[seckey]
            valuetble = sorted(valuetble, key = lambda sym : sym.value)
            idx = 0
            for sym in valuetble:
                nidx = idx + 1
                while nidx < len(valuetble):
                    if valuetble[idx].storagecls != IMAGE_SYM_CLASS_LABEL and valuetble[nidx].storagecls != IMAGE_SYM_CLASS_LABEL:
                        sym.size = valuetble[nidx].value - valuetble[idx].value
                        break
                    elif valuetble[idx].storagecls == IMAGE_SYM_CLASS_LABEL:
                        sym.size = valuetble[nidx].value - valuetble[idx].value
                        break
                    else:
                        logging.info('[%s][%d]%s [%d]%s'%(seckey,idx,valuetble[idx], nidx,valuetble[nidx]))
                    nidx += 1
                if nidx >= len(valuetble):                    
                    section = self.sections[seckey]
                    sym.size = section.size - valuetble[idx].value
                idx += 1
            self.__symtables[seckey] = valuetble
        return

    def __parse_reloc(self,data):
        basesymoff = self.__symoffset
        stroff = self.__stroffset
        strend = (self.__stroffset + self.__strsize)
        self.__relocs = dict()
        idx = 0
        for section in self.sections:
            idx += 1
            seckey = (idx - 1)
            self.__relocs[seckey] = []
            if section.offrel != 0 and (section.flags & IMAGE_SCN_CNT_CODE) != 0 and (section.flags & IMAGE_SCN_LNK_COMDAT) == 0:
                curreloff = section.offrel
                for i in range(section.numrels):
                    rel = CoffReloc(data,curreloff,basesymoff, stroff,strend)
                    if self.__header.id == 0x8664:
                        if rel.type >= IMAGE_REL_AMD64_REL32  and rel.type <= IMAGE_REL_AMD64_REL32_5:
                            rel.size = 4
                            self.__relocs[seckey].append(rel)
                    elif self.__header.id == 0x14c:
                        if rel.type == IMAGE_REL_I386_DIR32  or rel.type == IMAGE_REL_I386_DIR32NB  or rel.type == IMAGE_REL_I386_REL32 :
                            self.__relocs[seckey].append(rel)
                            rel.size = 4
                    curreloff += rel.get_size()
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
        self.__parse_reloc(data)
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


