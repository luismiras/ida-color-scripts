'''
palette_offsets.py

These are the offsets into IDA's palettes.


'''

__all__ = ['all_palettes']

class PaletteStore(object):

	def __init__(self, name, size, p_items, p_items_offsets):
		self.name = name
		self.size = size
		self.data = None
		self.p_items = p_items
		self.p_items_offsets = p_items_offsets
		return 


Palette_items_offsets = {
"Default color": 0x0010,
"Regular comment": 0x0014,
"Repeatable comment": 0x0018,
"Automatic comment": 0x001c,
"Instruction": 0x0020,
"Dummy data name": 0x0024,
"Regular data name": 0x0028,
"Demangled name": 0x002c,
"Punctuation": 0x0030,
"Char in instruction": 0x0034,
"String in instruction": 0x0038,
"Number in instruction": 0x003c,
"Suspicious constant": 0x0040,
"Code reference": 0x0044,
"Data reference": 0x0048,
"Code reference to tail": 0x004c,
"Data reference to tail": 0x0050,
"Error": 0x0054,
"Opcode bytes": 0x005c,
"Extra line": 0x0060,
"Manual operand": 0x0064,
"Hidden name": 0x0068,
"Library function name": 0x006c,
"Local variable name": 0x0070,
"Dummy code name": 0x0074,
"Directive": 0x0078,
"Macro name": 0x007c,
"String in data": 0x0080,
"Char in data": 0x0084,
"Number in data": 0x0088,
"Other keywords": 0x008c,
"Register name": 0x0090,
"Imported name": 0x0094,
"Segment name": 0x0098,
"Dummy unexplored name": 0x009c,
"Regular code name": 0x00a0,
"Regular unexplored name": 0x00a4,
"Collapsed line": 0x00a8,
"Disassembly Background": 0x00b0,
"Selection Background": 0x00b4,
"Line prefix, library function": 0x00b8,
"Line prefix, regular function": 0x00bc,
"Line prefix, instruction": 0x00c0,
"Line prefix, data": 0x00c4,
"Line prefix, unexplored": 0x00c8,
"Line prefix, externs": 0x00cc,
"Line prefix, current item": 0x00d0,
"Line prefix, current line": 0x00d4}
 
Palette_items = [
"Default color",
"Disassembly Background",
"Selection Background",
"Instruction",
"Directive",
"Macro name",
"Register name",
"Other keywords",
"Dummy data name",
"Dummy code name",
"Dummy unexplored name",
"Hidden name",
"Library function name",
"Local variable name",
"Regular data name",
"Regular code name",
"Regular unexplored name",
"Demangled name",
"Segment name",
"Imported name",
"Suspicious constant",
"Char in instruction",
"String in instruction",
"Number in instruction",
"Char in data",
"String in data",
"Number in data",
"Code reference",
"Data reference",
"Code reference to tail",
"Data reference to tail",
"Automatic comment",
"Regular comment",
"Repeatable comment",
"Extra line",
"Collapsed line",
"Line prefix, library function",
"Line prefix, regular function",
"Line prefix, instruction",
"Line prefix, data",
"Line prefix, unexplored",
"Line prefix, externs",
"Line prefix, current item",
"Line prefix, current line",
"Punctuation",
"Opcode bytes",
"Manual operand",
"Error"]


NavPalette_items_offsets = {
"Library function": 0x0000,
"Regular function": 0x0004,
"Instruction": 0x0008,
"Data": 0x000c,
"Unexplored": 0x0010,
"External symbol": 0x0014,
"Error": 0x0018,
"Gaps": 0x001c,
"Cursor": 0x0020}

NavPalette_items = [
"Library function",
"Regular function",
"Instruction",
"Data",
"Unexplored",
"External symbol",
"Error",
"Gaps",
"Cursor"]

NavPaletteExtended_items_offsets = {
"Address": 0x0000}

NavPaletteExtended_items = [
"Address"]

DebuggerPalette_items_offsets = {
"CurrentIP_bg_None": 0x0000,
"CurrentIP_bg_Enabled": 0x0004,
"CurrentIP_bg_Disabled": 0x0008,
"CurrentIP_bg_Unavailable": 0x0018,
"Address_bg_None": 0x000c,
"Address_bg_Enabled": 0x0010,
"Address_bg_Disabled": 0x0014,
"Address_bg_Unavailable": 0x001c,
"Registers_None": 0x0020,
"Registers_Enabled": 0x0024,
"Registers_Disabled": 0x0028}

DebuggerPalette_items = [
"CurrentIP_bg_None",
"CurrentIP_bg_Enabled",
"CurrentIP_bg_Disabled",
"CurrentIP_bg_Unavailable",
"Address_bg_None",
"Address_bg_Enabled",
"Address_bg_Disabled",
"Address_bg_Unavailable",
"Registers_None",
"Registers_Enabled",
"Registers_Disabled"]

ArrowsPalette_items_offsets = {
"Jump in current function": 0x0000,
"Jump external to function": 0x0004,
"Jump under the cursor": 0x0008,
"Jump target": 0x000c,
"Register target": 0x0010}

ArrowsPalette_items = [
"Jump in current function",
"Jump external to function",
"Jump under the cursor",
"Jump target",
"Register target"]

GraphPalette_items_offsets = {
"Top color": 0x0000,
"Bottom color": 0x0004,
"Normal title": 0x0008,
"Selected title": 0x000c,
"Current title": 0x0010,
"Group frame": 0x0014,
"Node shadow": 0x0018,
"Highlight color 1": 0x001c,
"Highlight color 2": 0x0020,
"Foreign node": 0x0024,
"Normal edge": 0x0028,
"Yes edge": 0x002c,
"No edge": 0x0030,
"Highlighted edge": 0x0034,
"Current edge": 0x0038}

GraphPalette_items = [
"Top color",
"Bottom color",
"Normal title",
"Selected title",
"Current title",
"Group frame",
"Node shadow",
"Highlight color 1",
"Highlight color 2",
"Foreign node",
"Normal edge",
"Yes edge",
"No edge",
"Highlighted edge",
"Current edge"]

MiscPalette_items_offsets = {
"Messages color": 0x0000,
"Messages background color": 0x0004,
"Patched bytes": 0x0008,
"Unsaved changed": 0x000c}

MiscPalette_items = [
"Messages color",
"Messages background color",
"Patched bytes",
"Unsaved changed"]

all_palettes = [PaletteStore("Palette", 0x34c, Palette_items, Palette_items_offsets),
PaletteStore("NavPalette", 0x24, NavPalette_items, NavPalette_items_offsets),
PaletteStore("NavPaletteExtended", 0x4, NavPaletteExtended_items, NavPaletteExtended_items_offsets),
PaletteStore("DebuggerPalette", 0x2c, DebuggerPalette_items, DebuggerPalette_items_offsets),
PaletteStore("ArrowsPalette", 0x14, ArrowsPalette_items, ArrowsPalette_items_offsets),
PaletteStore("GraphPalette", 0x3c, GraphPalette_items, GraphPalette_items_offsets),
PaletteStore("MiscPalette", 0x10, MiscPalette_items, MiscPalette_items_offsets)]
