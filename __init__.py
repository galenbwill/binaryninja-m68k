import sys
import os
import binaryninja

from .logging import log_debug, __module__
log_debug(f'm68k Plugin loaded from: {os.path.dirname(__module__.__loader__.path)}')

from .m68k import *
from .test import test_all
from binaryninja import Architecture, CallingConvention

#PluginCommand.register("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)
PluginCommand.register_for_address("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)

M68000.register()
M68008.register()
M68010.register()
M68020.register()
M68030.register()
M68040.register()
M68LC040.register()
M68EC040.register()
M68330.register()
M68340.register()

# BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])
BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])

class ParametersInRegistersCallingConvention(CallingConvention):
    name = "ParametersInRegisters"


arch = Architecture['M68000']
arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, 'default'))

BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])

test_all()
