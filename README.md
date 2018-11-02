# py-coff
> python common object file format parse for windows compiler

### Release History
* Nov 2nd 2018 Release 0.0.2 the first version to handle

### simple example
```python
import coff
import sys

def main():
	for v in sys.argv[1:]:
		cffmt = coff.Coff(v)
		idx = 0
		for seckey in cffmt.relocs.keys():
			section = cffmt.sections[seckey]
			relocs = cffmt.relocs[seckey]
			idx = 0
			sys.stdout.write('[%s].[%s]%s relocs\n'%(v,seckey,section))
			for rel in relocs:
				sys.stdout.write('    [%d] %s\n'%(idx,rel))
				idx += 1
		for seckey in cffmt.symtables.keys():
			idx = 0
			section = cffmt.sections[seckey]
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

main()
```


> if the command line like this
> python example.py main.obj

> result is like this

```shell
[main.obj].[0]CoffSectionHeader(name[.chks64];paddr[0x0];vaddr[0x0];size[0x350];offdata[0x490d6];offrel[0x0];numrels[0x0];lineentries[0x0];numlnno[0x0];flags[0xa00(INFO;REMOVE)]) relocs
[main.obj].[1]CoffSectionHeader(name[.drectve];paddr[0x0];vaddr[0x0];size[0xc4];offdata[0x10a4];offrel[0x0];numrels[0x0];lineentries[0x0];numlnno[0x0];flags[0x100a00(INFO;REMOVE;1 byte align)]) relocs
....
[104] CoffSectionHeader(name[.bss];paddr[0x0];vaddr[0x0];size[0x27d4];offdata[0x0];offrel[0x0];numrels[0x0];lineentries[0x0];numlnno[0x0];flags[0x-3fbfff80(BSS;8 bytes align;READ;WRITE)]) name
    [0] [?st_adddacl_cmdopts$initializer$@@3P6AXXZA] value[0x0]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [1] [?st_addsacl_cmdopts$initializer$@@3P6AXXZA] value[0x4]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [2] [?st_ansitoutf8_cmdopts$initializer$@@3P6AXXZA] value[0x8]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [3] [?st_clilap_cmdopts$initializer$@@3P6AXXZA] value[0xc]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [4] [?st_dumpdacl_cmdopts$initializer$@@3P6AXXZA] value[0x10]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [5] [?st_dumpsacl_cmdopts$initializer$@@3P6AXXZA] value[0x14]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [6] [?st_existsvc_cmdopts$initializer$@@3P6AXXZA] value[0x18]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [7] [?st_findwindow_cmdopts$initializer$@@3P6AXXZA] value[0x1c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [8] [?st_fullpath_cmdopts$initializer$@@3P6AXXZA] value[0x20]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [9] [?st_getacl_cmdopts$initializer$@@3P6AXXZA] value[0x24]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [10] [?st_getcompname_cmdopts$initializer$@@3P6AXXZA] value[0x28]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [11] [?st_getcp_cmdopts$initializer$@@3P6AXXZA] value[0x2c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [12] [?st_getsid_cmdopts$initializer$@@3P6AXXZA] value[0x30]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [13] [?st_iregexec_cmdopts$initializer$@@3P6AXXZA] value[0x34]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [14] [?st_main_cmdopts$initializer$@@3P6AXXZA] value[0xac]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [15] [?st_mktemp_cmdopts$initializer$@@3P6AXXZA] value[0x38]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [16] [?st_netinter_cmdopts$initializer$@@3P6AXXZA] value[0x3c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [17] [?st_outc_cmdopts$initializer$@@3P6AXXZA] value[0x40]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [18] [?st_pidargv_cmdopts$initializer$@@3P6AXXZA] value[0x44]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [19] [?st_quote_cmdopts$initializer$@@3P6AXXZA] value[0x48]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [20] [?st_readencode_cmdopts$initializer$@@3P6AXXZA] value[0x4c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [21] [?st_regbinget_cmdopts$initializer$@@3P6AXXZA] value[0x50]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [22] [?st_regbinset_cmdopts$initializer$@@3P6AXXZA] value[0x54]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [23] [?st_regexec_cmdopts$initializer$@@3P6AXXZA] value[0x58]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [24] [?st_removedacl_cmdopts$initializer$@@3P6AXXZA] value[0x5c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [25] [?st_removesacl_cmdopts$initializer$@@3P6AXXZA] value[0x60]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [26] [?st_run_cmdopts$initializer$@@3P6AXXZA] value[0x64]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [27] [?st_runevt_cmdopts$initializer$@@3P6AXXZA] value[0x68]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [28] [?st_runsevt_cmdopts$initializer$@@3P6AXXZA] value[0x6c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [29] [?st_runsingle_cmdopts$initializer$@@3P6AXXZA] value[0x70]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [30] [?st_runv_cmdopts$initializer$@@3P6AXXZA] value[0x74]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [31] [?st_runvevt_cmdopts$initializer$@@3P6AXXZA] value[0x78]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [32] [?st_sendmsg_cmdopts$initializer$@@3P6AXXZA] value[0x7c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [33] [?st_setcompname_cmdopts$initializer$@@3P6AXXZA] value[0x80]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [34] [?st_setcp_cmdopts$initializer$@@3P6AXXZA] value[0x84]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [35] [?st_setgroup_cmdopts$initializer$@@3P6AXXZA] value[0x88]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [36] [?st_setowner_cmdopts$initializer$@@3P6AXXZA] value[0x8c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [37] [?st_svchdl_cmdopts$initializer$@@3P6AXXZA] value[0x90]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [38] [?st_svcmode_cmdopts$initializer$@@3P6AXXZA] value[0x94]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [39] [?st_svcstate_cmdopts$initializer$@@3P6AXXZA] value[0x98]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [40] [?st_svrlap_cmdopts$initializer$@@3P6AXXZA] value[0x9c]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [41] [?st_utf8toansi_cmdopts$initializer$@@3P6AXXZA] value[0xa0]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [42] [?st_winver_cmdopts$initializer$@@3P6AXXZA] value[0xa4]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
    [43] [?st_winverify_cmdopts$initializer$@@3P6AXXZA] value[0xa8]sectnum[105]type[0x0]storagecls[0x3(STATIC)]numaux[0]size[0x4]
```

## variable description
> variables in the Coff
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
fname | the file name input for Coff |  |
header | coff header in the file |  |
opthdr | coff opt header in the file ,it will be None if no opt header |  |
sections | array of the section in the coff file |  |
relocs | dictionary for every sections relocations |  |
symtables | dictionary symtables for every sections , it has value sorted and name sorted |  |


## variable for CoffHeader [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#coff-file-header-object-and-image)
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
id | id of the compiled for |  |
numsects | number of sections |  |
timestamp | time stamp created for created coff file |  |
symtab | file pointer of the symtable in the coff file |  |
symnums | sym numbers in the symtable |  |
optsize | opt header size ==0 means no opt header |  |
flags | flag indicate for the flags [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#characteristics) |  |
symtab | file pointer of the symtable in the coff file |  |

## variable for OptHeader 
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
magic | magic number for optheader |  |
version | version for optheader |  |
szexe | size of code |  |
szdata | size of data |  |
szbss | size of bss |  |
entry | entry for program |  |
startex | file position for code |  |
startdata | file position for data |  |

## variable for Section [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-table-section-headers)
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
name | name for the section | at most 8 bytes  |
paddr | physical address loaded of the section |  |
vaddr | virtual load address of the section |  |
size | size of raw data in the section |  |
offdata | file position of the section raw data |  |
offrel | file position of the section relocation data |  |
numrels | number for the relocations for this section relocation data |  |
numlnno | obsolete |  |
lineentries | obsolete |  |
flags | flags for the section [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-flags) |  |

## variable for syms [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#coff-symbol-table)
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
name | name for the symbol [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#symbol-name-representation)|   |
value | offset from the section rawdata |   |
sectnum | associated section number ,it is the idx of section + 1 [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-number-values)|   |
type | type of the symbol [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#type-representation)|   |
storagecls | stored object type [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#storage-class)|   |
numaux |  number auxiliary symbol for this symbol [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#auxiliary-symbol-records)|   |


## variable for relocations [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#coff-relocations-object-only)
-----------------
name  | description |  Example |
| :------------: |:---------------|:---------------|
name | name for the relocation [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#symbol-name-representation)|   |
vaddr | offset in the raw data section |   |
type | type of the relocation [see](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#type-indicators)|   |
