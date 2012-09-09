'''
quick hack to import IDA color theme from exported Windows reg file.

This script generates a new config file. Backup your original.
WorksForMe(tm)

[HKEY_CURRENT_USER\Software\Hex-Rays\IDA]

A theme consists of:
  AutoHighlightColorQ 
  HintColorQ
  and the Palettes

Non QT versions ex. AutoHighlightColor are legacy for idag.exe

I don't have the Linux version but I assume its the same as OS X.

I tried standard crc32 from zlib and binascii but IDA's appears to be
different. ctypes are used to call into IDA's calc_crc32 function 

NOTES:
Since IDA is compiled for 32 bits, you must use 32bit Python for ctypes 
to work. The following worked for me:
$ export VERSIONER_PYTHON_PREFER_32_BIT=Yes

This script just patches over old colors. Colors (ColorQs, Palettes)
need to be present in the config. If they aren't there, just set one 
and they will all get written out to the config. Set the Highlight color
and exit IDA. Then you can rerun the script.

'''
import sys
import os

import ctypes

from optparse import OptionParser
from binascii import hexlify, unhexlify
from struct import pack, unpack


IDA_REG = os.path.expanduser("~/.idapro/ida.reg")
IDA_DYLIB = "/Applications/IDA Pro 6.3/IDA binaries/libida.dylib"
IDA_MAGIC = 0x37614469
colorq = ["HintColorQ", "AutoHighlightColorQ"] 
palettes = {"Palette": 0x34c, 
"NavPalette": 0x24, 
"NavPaletteExtended": 0x4, 
"DebuggerPalette": 0x2c, 
"ArrowsPalette": 0x14, 
"GraphPalette": 0x3c, 
"MiscPalette": 0x10} 
REG_BINARY = 3
REG_DWORD = 4

ida_theme = {}


def extract_key_and_type(line):

    if line[0] != "\"":
        print "fail"
        return None, None

    key_end = line.find("\"=")
    if key_end == -1:
        print "fail"
        return None, None
    key = line[1:key_end] 

    if line[key_end+2:].find("dword:") == 0:
        return key, "dword"

    if line[key_end+2:].find("hex:") == 0:
        return key, "hex"

    return key, "other"

def raw_data_to_lines(raw_data):

    data = ""
    r_len = len(raw_data[2:])
    for x in range(2, r_len, 2):
        data += raw_data[x]

    raw_lines = data.split("\r\n")

    lines = []
    # remove empty lines and comments
    for x in raw_lines:
        if x == "":
            continue
        if x[0] == ";":
            continue
        lines.append(x)
    return lines


def clean_hex_line(hex_line):
    return hex_line.strip(' \\').replace(',','')

def parse_reg_file(filename, debug=False):
    
    print "[*] parsing winreg file: %s" % filename
    fd = open(filename, "rb")
    raw_data = fd.read()
    fd.close()

    if raw_data[:2] != "\xff\xfe":
        print "ERROR: %s has bad header bytes" % filename
        return False

    lines = raw_data_to_lines(raw_data)

    if lines[0] != "Windows Registry Editor Version 5.00":
        print "ERROR: bad reg file format"
        return False

    reg_start = None
    for x in range(len(lines)):
        if lines[x] == "[HKEY_CURRENT_USER\Software\Hex-Rays\IDA]":
            reg_start = x+1
            break

    if reg_start == None:
        print "ERROR: bad reg file, no IDA data"
        return False

    curr_line = reg_start
    while curr_line < len(lines):
        line = lines[curr_line]
        if line[0] == "[":
            break
        if line[0] == "\"":
            r_key, r_type = extract_key_and_type(line)
            if r_key in colorq:
                # should test type as well
                tmp = line.find("=dword:")
                # should test for -1
                r_val = int(line[tmp+len("=dword:"):], 16)
                if debug:
                    print "%s : %.8x" % (r_key, r_val)
                ida_theme[r_key] = r_val

            if r_key in palettes.keys():
                if debug:
                    print r_key
                r_val = ""
                tmp = line.find("=hex:")
                tmp_line = line[tmp+len("=hex:"):]

                while tmp_line[-1] == "\\":
                    r_val += clean_hex_line(tmp_line)
                    curr_line += 1
                    tmp_line = lines[curr_line]
                r_val += clean_hex_line(tmp_line)
                if debug:
                    print "%x : %s" % (len(r_val)/2, r_val)

                # should verify right sizes
                ida_theme[r_key] = unhexlify(r_val)
        curr_line += 1

    return True


def replace_dword(data, r_key, r_val, debug=False):

    if debug:
        print "%s : dword" % r_key

    #\x00HintColorQ\x00 size type
    search_key = "%s%s%s%s%s" % (pack("<B", 0), r_key, pack("<B", 0), pack("<L", 4), pack("<B", REG_DWORD))
    offset = data.find(search_key)
    if offset == -1:
        print "FAIL find search key for %s" % r_key
        return None

    offset += len(search_key)
    mod_data =  data[:offset]
    mod_data += pack("<L", r_val)
    offset += 4
    mod_data += data[offset:]
    return mod_data


def replace_bin(data, r_key, r_val, debug=False):

    if debug:
        print "%s : hex" % r_key

    #\x00Palette\x00 size type
    search_key = "%s%s%s%s%s" % (pack("<B", 0), r_key, pack("<B", 0), pack("<L", palettes[r_key]), pack("<B", REG_BINARY))
    offset = data.find(search_key)
    if offset == -1:
        print "FAIL find search key for %s" % r_key
        print "     %s" % hexlify(search_key)
        #hexdump(data)
        return None

    offset += len(search_key)
    mod_data =  data[:offset]
    r_val = ida_theme[r_key]
    mod_data += r_val
    offset += len(r_val)
    mod_data += data[offset:]
    return mod_data


def recalc_crc32(data):

    dll = ctypes.cdll[IDA_DYLIB]
    calc_data = data[4:-4]
    c_data = ctypes.c_char_p(calc_data)
    crc32 = dll.calc_crc32(IDA_MAGIC, c_data, len(calc_data))

    return data[:-4] + pack("<L", crc32)


def write_new_config(src_filename, dst_filename):

    print "[*] reading in original config: %s" % src_filename
    fd = open(src_filename, "rb")
    i_data = fd.read()
    fd.close()

    print "[*] patching in new colors"
    for r_key in ida_theme.keys():
        if r_key in colorq:
            i_data = replace_dword(i_data, r_key, ida_theme[r_key])
        elif r_key in palettes:
            i_data = replace_bin(i_data, r_key, ida_theme[r_key])
        else:
            print "ERROR!!: write_new_config()"
            return False
        if i_data == None: # failed to find a searchkey
            print "Can't find a key. "
            print '''This script just patches over old colors. Colors (ColorQs, Palettes)
need to be present in the config. If they aren't there, just set one 
and they will all get written out to the config. Set the Highlight color
and exit IDA. Then you can rerun the script.'''
            return False
        
    print "[*] calculating new crc32"
    i_data = recalc_crc32(i_data)

    print "[*] writing out new config: %s" % dst_filename
    fd = open(dst_filename, "wb")
    fd.write(i_data)
    fd.close()
    return True

def main():

    usage = "usage: %prog [options]\n\n"
    usage += "\n"

    parser = OptionParser(usage, version="%prog v0.1")
    parser.add_option("-f", "--file", dest="ida_reg_filename",
                      help="path to ida.reg file.\ndefault is ~/.idapro/ida.reg")

    parser.add_option("-o", "--outfile", dest="out_filename",
                      help="generates new config and write to file")

    parser.add_option("-w", "--winregfile", dest="winreg_filename",
                      help="Windows registry file used to import colors")

    parser.add_option("-d", default=False,
                      action="store_true", dest="debug",
                      help="debug")


    (options, args) = parser.parse_args()

    if options.winreg_filename == None:
        parser.error("winregfile is required")

    if options.out_filename == None:
        parser.error("outfile is required")

    if options.ida_reg_filename != None:
        global IDA_REG
        IDA_REG = os.path.expanduser(options.ida_reg_filename)

    print "[*] ida_import_theme_osx.py"
    print "    windows registry file: %s" % options.winreg_filename
    print "    original config:       %s" % IDA_REG
    print "    new config:            %s" % options.out_filename

    parse_reg_file(options.winreg_filename)
    write_new_config(IDA_REG, options.out_filename)

if __name__ == "__main__":

    import struct
    arch = struct.calcsize("P") * 8    

    if arch == 32:
        main()
        sys.exit()

    print "You are running a 64bit version of python. This script uses ctypes to call into IDA for calc_crc32()."
    print "Try setting:\n export VERSIONER_PYTHON_PREFER_32_BIT=Yes"
    print "and run again"

