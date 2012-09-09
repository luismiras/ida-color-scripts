'''
export_IDA_colors.py v0.01

Copyright (c) 2012 Luis Miras


This script exports IDA's colors to a YAML based theme file.
The theme file lists individual colors. For example:

   	MiscPalette:
        Messages color: "#000000"
        Messages background color: "#ffffff"
        Patched bytes: "#804040"
        Unsaved changed: "#ff8000"

Tested on:
  * Windows
  * Mac OS X
  * Linux (untested)


TODO:
  better ida.reg parsing, move to a separate module
  create Windows reg files
  import functionality?

'''

import os.path
import yaml
from struct import pack, unpack
from binascii import hexlify, unhexlify
from optparse import OptionParser

from palette_offsets import all_palettes

try:
    from _winreg import *
except ImportError:
    # Linux or OS X

    win32 = False	
    ida_key = os.path.expanduser("~/.idapro/ida.reg")

    REG_BINARY = 3
    REG_DWORD = 4

    HKEY_CURRENT_USER = 0 # dont care
    KEY_READ  = "rb" # could just be "r" in non win
else:
    print "else import"
    # Windows
    win32 = True	
    ida_key = r'Software\Hex-Rays\IDA'

# globals

default_theme_name = 'IDA reg export'
default_indent = 4

###########################################
# non Windows functions

#OpenKey(HKEY_CURRENT_USER, ida_key, 0, KEY_READ)
def OpenKey_nonWin(hive, ida_key, dont_care, mode):
    '''
    Function: OpenKey_nonWin

    This is a non Windows version equivalent of OpenKey()
    It works with the ida.reg file, which is used to emulate the registry.

    '''

    fd = open(ida_key, mode)
    key = fd.read()
    fd.close()
    return key 


# value, reg_type = QueryValueEx(key, name)
def QueryValueEx_nonWin(key, name):
    '''
    Function: QueryValueEx_nonWin

    This is a non Windows version equivalent of QueryValueEx().
    It works with the ida.reg file, which is used to emulate the registry.

    Only two types are supported REG_DWORD and REG_BINARY.
    '''
    value = None

    x = key.find(name)
    while x != -1:
        if key[x-1].isalpha() == True:
            x += len(name)
            # redefine key to keep looking
            key = key[x+1:]
            x = key.find(name)
            continue
        #found our name, skip over NULL
        x += len(name)+1
        #extract size
        size = unpack("<L", key[x:x+4])[0]
        x += 4
        # extract type
        reg_type = ord(key[x])
        x += 1

        if reg_type == REG_DWORD:
            # could check for length of 4
            value = unpack("<L", key[x:x+4])[0]
        elif reg_type == REG_BINARY:
            value = key[x:x+size]
        else:
            raise Exception("QueryValueEx", "wrong reg_type")
        break
    if value == None:
        raise Exception("QueryValueEx", "name not found")

    return value, reg_type


def CloseKey_nonWin(key):
    '''
    Function: CloseKey_nonWin

    This is a non Windows version equivalent of CloseKey().

    This function does nothing.
    '''
    return


if win32 == False:	
    OpenKey = OpenKey_nonWin
    QueryValueEx = QueryValueEx_nonWin
    CloseKey = CloseKey_nonWin



class IDAColors(object):
    '''
    Class: IDAColors

    This class performs all the color extraction for palettes and other colors.
    It all builds yaml and C files.
    '''
    def __init__(self):
        '''

        '''

        self.key = None
        self.collected_colors = False

        self.fd = None
        self.HintColorQ = None
        self.AutoHighlightColorQ = None

        self.yaml_text_data = None
        self.indent = 0

    ###########################################
    # exported methods

    def export_yaml(self, filename, theme_name=default_theme_name, indent=default_indent):
        '''

        '''
        if self.yaml_text_data == None:
            self.make_theme(theme_name, indent)

        self.indent = indent

        self.fd = open(filename, "w")
        self.fd.write(self.yaml_text_data)
        self.fd.close()

        return

    def export_C_source(self, filename="colors.c", var_prefix="_"):
        '''

        '''

        if not self.collected_colors:
            self.collect_colors()

        self.fd = open(filename, "w")

        self.fd.write("// exported colors\n\n")

        for palette in all_palettes:			
            var_line = "char* %s%s = \"" % (var_prefix, palette.name)
            self.fd.write(var_line)
            data = palette.data
            count = 0
            line1 = True
            line_count = 16 - len(var_line)/4
            for x in range(len(palette.data)):
                if x != 0 and count == line_count:
                    self.fd.write("\"\\\n\"")
                    count = 0
                    if line1:
                        line1 = False
                        line_count = 16
                self.fd.write("\\x%.2x" % ord(palette.data[x]))
                count += 1
            self.fd.write("\";\n\n")

        self.fd.write("unsigned int %s%s = 0x%.8x\n\n" % (var_prefix, "HintColorQ", self.HintColorQ))
        self.fd.write("unsigned int %s%s = 0x%.8x\n\n" % (var_prefix, "AutoHighlightColorQ", self.AutoHighlightColorQ))
        self.fd.close()
        self.fd = None
        return


    def show_yamltext(self, theme_name=default_theme_name, indent=default_indent):
        '''

        '''
        if self.yaml_text_data == None:
            self.make_theme(theme_name, indent)

        print self.yaml_text_data
        return

    def show_yamldump(self, theme_name=default_theme_name, indent=default_indent):
        '''

        '''
        if self.yaml_text_data == None:
            self.make_theme(theme_name, indent)

        print yaml.dump(yaml.load(self.yaml_text_data))
        return

    def show_hexdump(self):
        '''

        '''
        if not self.collected_colors:
            self.collect_colors()

        for palette in all_palettes:
            print "%s (0x%x):" % (palette.name, palette.size)
            self.dump_hex(palette.data)

        print "%s:\n0x%.8x\n" % ("HintColorQ", self.HintColorQ)
        print "%s:\n0x%.8x\n" % ("AutoHighlightColorQ", self.AutoHighlightColorQ)
        return

    def dump_hex(self, data):
        '''

        '''
        if data == None:
            print "fail"
            exit(0)
        for x in range(len(data)):
            if x != 0 and x % 16 == 0:
                print ""
            print "%.2x " % ord(data[x]),
        print "\n"

    ###########################################
    # gets colors

    def collect_colors(self):
        '''

        '''
        try:
            self.key = OpenKey(HKEY_CURRENT_USER, ida_key, 0, KEY_READ)
        except Exception, e:
            print "ERROR: cant open key %s" % ida_key
            print e
            exit(0)

        for pal in all_palettes:
            self.get_palette_data(pal)

        self.HintColorQ = self.query_dword_key("HintColorQ")
        self.AutoHighlightColorQ = self.query_dword_key("AutoHighlightColorQ")
        CloseKey(self.key)
        self.collected_colors = True

    def get_palette_data(self, palette):
        '''

        '''
        data = self.query_binary_key(palette.name, palette.size)
        palette.data = data

    ###########################################
    # query wrappers

    def query_binary_key(self, name, size):
        '''

        '''
        try:
            value, reg_type = QueryValueEx(self.key, name)
        except Exception, e:
            print "ERROR: cant read key %s" % name
            print e
            exit(0)

        if reg_type != REG_BINARY:
            print "ERROR: %s not REG_BINARY" % name
            return None

        if len(value) != size:
            print "ERROR: %s size mismatch, expected: 0x%x actual: 0x%x" % (name, size, len(value))
            return None

        return value

    def query_dword_key(self, name):
        '''

        '''
        try:
            value, reg_type = QueryValueEx(self.key, name)
        except Exception, e:
            print "ERROR: cant read key %s" % name
            print e
            exit(0)
        if reg_type != REG_DWORD:
            print "ERROR: %s not REG_DWORD" % name
            return None
        return value

    ##########################################
    # conversions

    def dword_to_rgb(self, dword):
        '''
        converts a dword value to a color string, "#112233".
        '''
        if type(dword) != int or ((dword & 0xff000000) >> 24) != 0:
            raise Exception("dword_to_rgb", "bad dword")
        rgb_data = "\"#%.2x%.2x%.2x\"" % ((dword & 0x000000FF),((dword & 0x0000ff00) >> 8),((dword & 0x00ff0000) >> 16))
        return rgb_data


    def bin_to_rgb(self, bin_data):
        '''
        converts a 4 byte binary string to a color string, "#112233".
        '''
        if len(bin_data) != 4 or bin_data[3] != '\x00':
            raise Exception("bin_to_rgb", "bad bin_data")
        rgb_data = "\"#%s\"" % hexlify(bin_data[:3])
        return rgb_data

    def rgb_to_bin(self, rgb_data):
        '''
        converts a color string, "#112233", to 4 byte binary string
        '''
        if len(rgb_data) != 7 or rgb_data[0] != '#' or not rgb_data[1:].isalpha():
            raise Exception("rgb_to_bin", "bad rgb_data")
        bin_data = unhexlify(rgb_data[1:]+"00")
        return bin_data


    ##########################################
    # yaml creation 


    def make_palette_yaml(self, palette, indent_level, indent):
        '''

        '''

        y_data = "%s%s:\n" % (indent_level*indent*" ", palette.name)
        indent_level += 1

        for item in palette.p_items:
            offset = palette.p_items_offsets[item]
            color = self.bin_to_rgb(palette.data[offset:offset+4])
            y_data += "%s%s: %s\n" % (indent_level*indent*" ", item, color)
        return y_data 


    def make_all_palettes_yaml(self, indent_level, indent):
        '''

        '''

        y_data = ""
        for p in all_palettes:
            y_data += self.make_palette_yaml(p, indent_level, indent)
        return y_data

    def make_colorq(self, indent_level, indent):
        '''

        '''

        y_data = "%sHintColorQ: %s\n" % ((indent_level*indent*" "), self.dword_to_rgb(self.HintColorQ))
        y_data += "%sAutoHighlightColorQ: %s\n" % ((indent_level*indent*" "), self.dword_to_rgb(self.AutoHighlightColorQ))
        return y_data

    def make_settings(self, indent_level, indent):
        '''

        '''
        y_data = "%sSettings:\n" % (indent_level*indent*" ")
        y_data += self.make_all_palettes_yaml(indent_level+1, indent)
        y_data += self.make_colorq(indent_level+1, indent)
        return y_data


    def make_theme(self, theme_name, indent):
        '''

        '''

        if not self.collected_colors:
            self.collect_colors()

        y_data = "Theme:\n"
        y_data += "%sName: %s\n" % (indent*" ", theme_name)
        y_data += self.make_settings(1, indent)
        self.yaml_text_data = y_data
        return

##################################################



def main():
    usage = "usage: %prog [options]\n\n"
    usage += "This script reads color values from the registry or registry file.\n"
    usage += "The colors can be exported to various formats:\n"
    usage += " * yaml.text     - Theme export format. The yaml file has individual color values.\n"
    usage += "                   Keeps the same order allowing easy diffing of themes.\n"
    usage += " * C source file - Takes the raw registry exports it to C char arrays.\n"
    usage += " * registry file - Windows registry file format. Only exports colors.\n"
    usage += "                   Prevents leaking of non color registry keys.\n\n"
    usage += "There are also flags to dump info to console."

    parser = OptionParser(usage, version="%prog v0.1")
    parser.add_option("-f", "--file", dest="ida_reg_filename",
                      help="path to ida.reg file.\ndefault is ~/.idapro/ida.reg")

    parser.add_option("-y", "--yamlfile", dest="yaml_filename",
                      help="generate yaml text and write to file")

    parser.add_option("-c", "--cfile", dest="c_filename",
                      help="generate C source file with colors from registry or ida.reg")

    parser.add_option("-r", "--rfile", dest="r_filename",
                      help="generate Windows registry file. (NOT WORKING)")

    parser.add_option("-s", default=False,
                      action="store_true", dest="show_yamltext",
                      help="Show yaml text")

    parser.add_option("-d", default=False,
                      action="store_true", dest="show_yamldump",
                      help="Show yaml.dump(yaml.load(text.yaml)).")

    parser.add_option("-x", default=False,
                      action="store_true", dest="show_hexdump",
                      help="Show hex dump of raw registry values.")


    (options, args) = parser.parse_args()

    if options.r_filename != None:
        parser.error("Windows registry export not implemented.")

    if options.yaml_filename == None and options.c_filename == None and options.show_yamltext == False\
       and options.show_yamldump == False and options.show_hexdump == False:
        parser.error("at least one option is needed")

    colors = IDAColors()

    if options.ida_reg_filename != None:
        global ida_key
        ida_key = os.path.expanduser(options.ida_reg_filename)
        print "[+] Setting ida.reg to: %s" % ida_key

    if options.show_hexdump:
        print "[+] hex dump:"
        colors.show_hexdump()

    if options.show_yamltext:
        print "[+] yaml text:"
        colors.show_yamltext()

    if options.show_yamldump:
        print "[+] yaml format dump:"
        colors.show_yamldump()

    if options.yaml_filename != None:
        print "[+] writing yaml text to: %s" % options.yaml_filename
        colors.export_yaml(options.yaml_filename)

    if options.c_filename != None:
        print "[+] writing C source to: %s" % options.c_filename
        colors.export_C_source(options.c_filename)

    return


if __name__ == "__main__":
    main()