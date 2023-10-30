"""

Copyright (c) 2017 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import struct
import traceback
import os

from binaryninja.architecture import Architecture, RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel, LLIL_TEMP
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import AddressField, ChoiceField, get_form_input
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (Endianness, BranchType, InstructionTextTokenType,
        LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag,
        ImplicitRegisterExtend, SymbolType)
from binaryninja import BinaryViewType

from .m68k_ops import *

class M68KDisasm:
    address_size = None
    control_registers = None

    def __init__(self, address_size, control_registers):
        self.address_size = address_size
        self.control_registers = control_registers

    def decode_effective_address(self, mode: int, register: int, data: bytes, size: Optional[int] = None) -> Tuple[Optional[Operand], Optional[int]]:
        mode &= 0x07
        register &= 0x07

        reg = None

        if mode == 0:
            # data register direct
            return (OpRegisterDirect(size, Registers[register]), 0)
        elif mode == 1:
            # address register direct
            return (OpRegisterDirect(size, Registers[register+8]), 0)
        elif mode == 2:
            # address register indirect
            return (OpRegisterIndirect(size, Registers[register+8]), 0)
        elif mode == 3:
            # address register indirect with postincrement
            return (OpRegisterIndirectPostincrement(size, Registers[register+8]), 0)
        elif mode == 4:
            # address register indirect with predecrement
            return (OpRegisterIndirectPredecrement(size, Registers[register+8]), 0)
        elif mode == 5:
            # address register indirect with displacement
            return (OpRegisterIndirectDisplacement(size, Registers[register+8], struct.unpack_from('>h', data, 0)[0]), 2)
        elif mode == 6:
            # extended addressing mode
            reg = Registers[register+8]
        elif mode == 7:
            if register == 0:
                # absolute short
                val = struct.unpack_from('>H', data, 0)[0]
                if val & 0x8000:
                    if self.address_size == 4:
                        val |= 0xffff0000 # extend to 32-bits
                    else:
                        val |= 0xff0000 # extend to 24-bits (for 68000)
                return (OpAbsolute(size, val, 1, self.address_size), 2)
            if register == 1:
                # absolute long
                return (OpAbsolute(size, struct.unpack_from('>L', data, 0)[0], 2, self.address_size), 4)
            elif register == 2:
                # program counter indirect with displacement
                return (OpRegisterIndirectDisplacement(size, 'pc', struct.unpack_from('>h', data, 0)[0]), 2)
            elif register == 3:
                # extended addressing mode
                reg = 'pc'
            elif register == 4:
                # immediate
                if size == None:
                    # unspecified length
                    return (OpImmediate(size, None), None)
                elif size == SIZE_BYTE:
                    # byte
                    return (OpImmediate(size, struct.unpack_from('>b', data, 1)[0]), 2)
                elif size == 1:
                    # word
                    return (OpImmediate(size, struct.unpack_from('>h', data, 0)[0]), 2)
                elif size == 2:
                    # long
                    return (OpImmediate(size, struct.unpack_from('>l', data, 0)[0]), 4)

        if reg is not None:
            extra = struct.unpack_from('>H', data, 0)[0]
            # index register
            xn = Registers[extra >> 12]
            # index register size
            index_size = (extra >> 11) & 1
            # index register scale
            scale = 1 << ((extra >> 9) & 3)
            length = 2

            if extra & 0x0100:
                # full extension word
                bd = 0
                od = 0

                # base displacement
                if not (extra >> 7) & 1:
                    if (extra >> 4) & 3 == 2:
                        # word base displacement
                        bd = struct.unpack_from('>h', data, length)[0]
                        length += 2
                    elif (extra >> 4) & 3 == 3:
                        # long base displacement
                        bd = struct.unpack_from('>L', data, length)[0]
                        length += 4

                # outer displacement
                if extra & 3 == 2:
                    # word outer displacement
                    od = struct.unpack_from('>h', data, length)[0]
                    length += 2
                elif extra & 3 == 3:
                    # long outer displacement
                    od = struct.unpack_from('>L', data, length)[0]
                    length += 4

                # suppress index register
                if extra & 7 == 0:
                    return (OpRegisterIndirectIndex(size, reg, bd, xn, index_size, scale), length)
                elif (extra >> 6) & 1:
                    return (OpMemoryIndirect(size, reg, bd, od), length)
                elif (extra >> 2) & 1:
                    return (OpMemoryIndirectPostindex(size, reg, bd, xn, index_size, scale, od), length)
                else:
                    return (OpMemoryIndirectPreindex(size, reg, bd, xn, index_size, scale, od), length)
            else:
                # brief extension word
                # 8 bit displacement
                d8 = extra & 0xff
                if d8 & 0x80:
                    d8 -= 256
                return (OpRegisterIndirectIndex(size, reg, d8, xn, index_size, scale), length)

        return (None, None)

    def decode_instruction(self, data: bytes, addr: int) -> Tuple[str, int, Optional[int], Optional[Operand], Optional[Operand], Optional[Operand]]:
        error_value = ('unimplemented', len(data), None, None, None, None)
        if len(data) < 2:
            return error_value

        instruction = struct.unpack_from('>H', data)[0]

        msb = instruction >> 8
        operation_code = msb >> 4

        #print((hex(addr), hex(instruction)))

        instr = None
        length = None
        size = None
        source = None
        dest = None
        third = None

        if operation_code == 0x0:
            # Bit manipulation/MOVEP/Immed late
            if instruction & 0xf9c0 == 0x00c0:
                # rtm, callm, chk2, cmp2
                if instruction & 0xfff0 == 0x06c0:
                    instr = 'rtm'
                    dest = OpRegisterDirect(SIZE_LONG, Registers[instruction & 15])
                    length = 2
                elif instruction & 0xffc0 == 0x06c0:
                    instr = 'callm'
                    source = OpImmediate(SIZE_BYTE, struct.unpack_from('>B', data, 3)[0])
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[4:], SIZE_BYTE) # check
                    if extra_dest is None:
                        return error_value
                    length = 4+extra_dest
                else:
                    size = (instruction >> 9) & 3
                    extra = struct.unpack_from('>H', data, 2)[0]
                    if extra & 0x0800:
                        instr = 'chk2'
                    else:
                        instr = 'cmp2'
                    source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[4:], SIZE_BYTE) # check
                    dest = OpRegisterDirect(size, Registers[(instruction >> 12) & 15])
                    if extra_source is None:
                        return error_value
                    length = 4+extra_source
            elif instruction & 0xffc0 in (0x0ac0, 0x0cc0, 0x0ec0):
                if instruction & 0xf9ff == 0x08fc:
                    instr = 'cas2'
                    size = ((instruction >> 9) & 3) - 1
                    extra1 = struct.unpack_from('>H', data, 2)[0]
                    extra2 = struct.unpack_from('>H', data, 4)[0]
                    source = OpRegisterDirectPair(size, Registers[extra1 & 7], Registers[extra2 & 7])
                    dest = OpRegisterDirectPair(size, Registers[(extra1 >> 6) & 7], Registers[(extra2 >> 6) & 7])
                    third = OpRegisterIndirectPair(size, Registers[(extra1 >> 12) & 15], Registers[(extra2 >> 12) & 15])
                    length = 6
                else:
                    instr = 'cas'
                    size = ((instruction >> 9) & 3) - 1
                    extra = struct.unpack_from('>H', data, 2)[0]
                    source = OpRegisterDirect(size, Registers[extra & 7])
                    dest = OpRegisterDirect(size, Registers[(extra >> 6) & 7])
                    third, extra_third = self.decode_effective_address(instruction >> 3, instruction, data[4:], size)
                    if extra_third is None:
                        return error_value
                    length = 4+extra_third
            elif msb in (0x00, 0x02, 0x04, 0x06, 0x0a, 0x0c):
                # ORI, ANDI, SUBI, ADDI, EORI, CMPI
                if msb == 0x00:
                    instr = 'ori'
                elif msb == 0x02:
                    instr = 'andi'
                elif msb == 0x04:
                    instr = 'subi'
                elif msb == 0x06:
                    instr = 'addi'
                elif msb == 0x0a:
                    instr = 'eori'
                elif msb == 0x0c:
                    instr = 'cmpi'
                size = (instruction >> 6) & 0x03
                source, extra_source = self.decode_effective_address(7, 4, data[2:], size)
                if instruction & 0x00ff == 0x003c:
                    dest = OpRegisterDirect(size, 'ccr')
                    extra_dest = 0
                elif instruction & 0x00ff == 0x007c:
                    dest = OpRegisterDirect(size, 'sr')
                    extra_dest = 0
                else:
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], size)

                if dest is None:
                    instr = None
                else:
                    length = 2+extra_source+extra_dest
            elif msb == 0x08:
                # btst, bchg, bclr, bset with constant
                if instruction & 0xffc0 == 0x0800:
                    instr = 'btst'
                elif instruction & 0xffc0 == 0x0840:
                    instr = 'bchg'
                elif instruction & 0xffc0 == 0x0880:
                    instr = 'bclr'
                elif instruction & 0xffc0 == 0x08C0:
                    instr = 'bset'
                source = OpImmediate(SIZE_BYTE, struct.unpack_from('>B', data, 3)[0])
                dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[4:], SIZE_BYTE)
                if isinstance(dest, OpRegisterDirect):
                    dest.size = SIZE_LONG
                if dest is None:
                    instr = None
                else:
                    length = 4+extra_dest
            elif msb & 0xf1 == 0x01:
                # movep, btst, bchg, bclr, bset with register
                if instruction & 0xf138 == 0x0108:
                    instr = 'movep'
                    size = ((instruction >> 6) & 1) + 1
                    source, extra_source = self.decode_effective_address(5, instruction, data[2:], SIZE_BYTE) # check
                    dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                    length = 2+extra_source
                    if instruction & 0x0080:
                        source, dest = dest, source
                else:
                    if instruction & 0xf1c0 == 0x0100:
                        instr = 'btst'
                    elif instruction & 0xf1c0 == 0x0140:
                        instr = 'bchg'
                    elif instruction & 0xf1c0 == 0x0180:
                        instr = 'bclr'
                    elif instruction & 0xf1c0 == 0x01c0:
                        instr = 'bset'
                    source = OpRegisterDirect(SIZE_BYTE, Registers[(instruction >> 9) & 7]) # check
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2:], SIZE_BYTE)
                    if isinstance(dest, OpRegisterDirect):
                        dest.size = SIZE_LONG
                    if dest is None:
                        instr = None
                    else:
                        length = 2+extra_dest
            elif instruction & 0xff00 == 0x0e00:
                instr = 'moves'
                extra = struct.unpack_from('>H', data, 2)[0]
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[extra >> 12])
                source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[4:], size)
                if extra & 0x0800:
                    source, dest = dest, source
                if extra_source is None:
                    return error_value
                length = 4+extra_source
        elif operation_code in (0x1, 0x2, 0x3):
            # move
            instr = 'move'
            if operation_code == 0x1:
                # Move byte
                size = SIZE_BYTE
            elif operation_code == 0x2:
                # Move long
                size = SIZE_LONG
            elif operation_code == 0x3:
                # Move word
                size = SIZE_WORD

            source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
            if source is None:
                instr = None
            else:
                dest, extra_dest = self.decode_effective_address(instruction >> 6, instruction >> 9, data[2+extra_source:], size)
                if dest is None or isinstance(dest, OpImmediate):
                    instr = None
                else:
                    if isinstance(dest, OpRegisterDirect) and (dest.reg[0] == 'a' or dest.reg == 'sp'):
                        instr = 'movea'
                    length = 2+extra_source+extra_dest
        elif operation_code == 0x4:
            # Miscellaneous
            extra_source = 0
            extra_dest = 0
            size = None
            skip_ea = False
            if instruction & 0xf100 == 0x4100:
                # lea, extb, chk
                if instruction & 0xf1c0 == 0x41c0:
                    if instruction & 0x0038:
                        instr = 'lea'
                        dest = OpRegisterDirect(SIZE_LONG, Registers[((instruction >> 9) & 7) + 8])
                    else:
                        instr = 'extb'
                    size = SIZE_LONG
                else:
                    instr = 'chk'
                    if instruction & 0x0080:
                        size = SIZE_WORD
                    else:
                        size = SIZE_LONG
                    dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
            elif msb == 0x40:
                # move from sr, negx
                if instruction & 0xffc0 == 0x40c0:
                    # move from sr
                    instr = 'move'
                    size = SIZE_WORD
                    source = OpRegisterDirect(size, 'sr')
                else:
                    instr = 'negx'
                    size = instruction >> 6
            elif msb == 0x42:
                # move to ccr, clr
                if instruction & 0xffc0 == 0x42c0:
                    # move to ccr
                    instr = 'move'
                    size = SIZE_WORD
                    source = OpRegisterDirect(size, 'ccr')
                else:
                    instr = 'clr'
                    size = instruction >> 6
            elif msb == 0x44:
                # move from ccr, neg
                if instruction & 0xffc0 == 0x44c0:
                    # move from ccr
                    instr = 'move'
                    size = SIZE_WORD
                    dest = OpRegisterDirect(size, 'ccr')
                else:
                    instr = 'neg'
                    size = instruction >> 6
            elif msb == 0x46:
                # move from sr, not
                if instruction & 0xffc0 == 0x46c0:
                    # move from sr
                    instr = 'move'
                    size = SIZE_WORD
                    dest = OpRegisterDirect(size, 'sr')
                else:
                    instr = 'not'
                    size = instruction >> 6
            elif msb in (0x48, 0x4c):
                # link, nbcd, movem, ext, swap, bkpt, pea, divs, divu, divsl, divul, muls, mulu
                if instruction & 0xfff8 == 0x4808:
                    instr = 'link'
                    size = SIZE_LONG
                    dest, extra_dest = self.decode_effective_address(7, 4, data[2:], size)
                elif instruction & 0xffc0 == 0x4800:
                    instr = 'nbcd'
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], SIZE_BYTE)
                    skip_ea = True
                elif instruction & 0xfb80 == 0x4880:
                    if instruction & 0x0040:
                        size = SIZE_LONG
                    else:
                        size = SIZE_WORD
                    if instruction & 0x0038:
                        instr = 'movem'
                        extra_source = 2
                        extra = struct.unpack_from('>H', data, 2)[0]
                        reg_list = []
                        if instruction & 0x0038 == 0x0020:
                            for k in range(16):
                                if extra << k & 0x8000:
                                    reg_list.append(Registers[k])
                        else:
                            for k in range(16):
                                if extra >> k & 0x0001:
                                    reg_list.append(Registers[k])
                        source = OpRegisterMovemList(size, reg_list)
                    else:
                        instr = 'ext'
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], size)
                    skip_ea = True
                    if instruction & 0x0400:
                        source, dest = dest, source
                elif instruction & 0xfff8 == 0x4840:
                    instr = 'swap'
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], SIZE_LONG)
                    skip_ea = True
                elif instruction & 0xfff8 == 0x4848:
                    instr = 'bkpt'
                    source = OpImmediate(SIZE_BYTE, instruction & 7)
                    skip_ea = True
                elif instruction & 0xffc0 == 0x4840:
                    instr = 'pea'
                    size = SIZE_LONG
                elif msb == 0x4c:
                    size = SIZE_LONG
                    extra_dest = 2
                    extra = struct.unpack_from('>H', data, 2)[0]
                    source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_dest:], size)
                    dh = Registers[extra & 7]
                    dl = Registers[(extra >> 12) & 7]
                    dest = OpRegisterDirect(size, dl)
                    if instruction & 0x0040:
                        if extra & 0x0800:
                            instr = 'divs'
                        else:
                            instr = 'divu'
                        if extra & 0x0400:
                            dest = OpRegisterDirectPair(size, dh, dl)
                        elif dh != dl:
                            dest = OpRegisterDirectPair(size, dh, dl)
                            instr += 'l'
                    else:
                        if extra & 0x0800:
                            instr = 'muls'
                        else:
                            instr = 'mulu'
                        if extra & 0x0400:
                            dest = OpRegisterDirectPair(size, dh, dl)
                    skip_ea = True
            elif msb == 0x4a:
                # bgnd, illegal, tas, tst
                if instruction == 0x4afa:
                    instr = 'bgnd'
                    skip_ea = True
                elif instruction == 0x4afc:
                    instr = 'illegal'
                    skip_ea = True
                elif instruction & 0xffc0 == 0x4ac0:
                    instr = 'tas'
                    skip_ea = True
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2:], SIZE_BYTE)
                else:
                    instr = 'tst'
                    size = instruction >> 6
            elif msb == 0x4e:
                # trap, link, unlk, move, reset, nop, stop, rte, rtd, rts, trapv, rtr, movec, jsr, jmp
                if instruction & 0xfff0 == 0x4e40:
                    instr = 'trap'
                    length = 2
                    source = OpImmediate(SIZE_BYTE, instruction & 15)
                    skip_ea = True
                elif instruction & 0xfff0 == 0x4e50:
                    if instruction & 0xfff8 == 0x4e50:
                        instr = 'link'
                        dest, extra_dest = self.decode_effective_address(7, 4, data[2:], 1)
                    else:
                        instr = 'unlk'
                    source = OpRegisterDirect(SIZE_LONG, Registers[(instruction & 7) + 8])
                    skip_ea = True
                elif instruction & 0xfff0 == 0x4e60:
                    instr = 'move'
                    size = SIZE_LONG
                    source = OpRegisterDirect(SIZE_LONG, Registers[(instruction & 7) + 8])
                    dest = OpRegisterDirect(size, 'usp')
                    if instruction & 0x08:
                        source, dest = dest, source
                    skip_ea = True
                elif instruction == 0x4e70:
                    instr = 'reset'
                    skip_ea = True
                elif instruction == 0x4e71:
                    instr = 'nop'
                    skip_ea = True
                elif instruction == 0x4e72:
                    instr = 'stop'
                    source = OpImmediate(SIZE_WORD, struct.unpack_from(">H", data, 2)[0])
                    extra_source = 2
                    skip_ea = True
                elif instruction == 0x4e73:
                    instr = 'rte'
                    skip_ea = True
                elif instruction == 0x4e74:
                    instr = 'rtd'
                    dest, extra_dest = self.decode_effective_address(7, 4, data[2:], SIZE_WORD)
                    skip_ea = True
                elif instruction == 0x4e75:
                    instr = 'rts'
                    skip_ea = True
                elif instruction == 0x4e76:
                    instr = 'trapv'
                    skip_ea = True
                elif instruction == 0x4e77:
                    instr = 'rtr'
                    skip_ea = True
                elif instruction & 0xfffe == 0x4e7A:
                    instr = 'movec'
                    size = SIZE_LONG
                    extended = struct.unpack_from('>H', data, 2)[0]
                    control_reg = self.control_registers.get(extended & 0x0fff, None)
                    reg = (extended >> 12) & 15
                    if control_reg is None:
                        instr = None
                    else:
                        source = OpRegisterDirect(size, control_reg)
                        dest = OpRegisterDirect(size, Registers[reg])
                        if instruction & 1:
                            source, dest = dest, source
                    extra_source = 2
                    skip_ea = True
                elif instruction & 0xff80 == 0x4e80:
                    if instruction & 0xffc0 == 0x4e80:
                        instr = 'jsr'
                    else:
                        instr = 'jmp'
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], SIZE_LONG)
                    skip_ea = True
            if instr is not None:
                if size is not None:
                    size &= 3
                if skip_ea:
                    pass
                elif dest is None:
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_source:], size)
                else:
                    source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2+extra_dest:], size)
                if extra_source is None or extra_dest is None:
                    instr = None
                else:
                    length = 2+extra_source+extra_dest
        elif operation_code == 0x5:
            # ADDQ/SUBQ/Scc/DBcc/TRAPcc
            if instruction & 0xf0c0 == 0x50c0:
                if instruction & 0xf0f8 == 0x50c8:
                    instr = 'db'+Condition[(instruction >> 8) & 0xf]
                    source = OpRegisterDirect(SIZE_WORD, Registers[instruction & 7])
                    dest = OpRegisterIndirectDisplacement(SIZE_LONG, 'pc', struct.unpack_from('>h', data, 2)[0])
                    length = 4
                elif instruction & 0xf0ff in (0x50fa, 0x50fb, 0x50fc):
                    instr = 'trap'+Condition[(instruction >> 8) & 0xf]
                    if instruction & 7 == 2:
                        length = 4
                        source = OpImmediate(SIZE_WORD, struct.unpack_from('>H', data, 2)[0])
                    elif instruction & 7 == 3:
                        length = 6
                        source = OpImmediate(SIZE_LONG, struct.unpack_from('>L', data, 2)[0])
                    elif instruction & 7 == 4:
                        length = 2
                else:
                    instr = 's'+Condition[(instruction >> 8) & 0xf]
                    size = SIZE_BYTE
                    dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                    if extra_dest is None:
                        return error_value
                    length = 2+extra_dest
            else:
                if instruction & 0x0100:
                    instr = 'subq'
                else:
                    instr = 'addq'
                val = (instruction >> 9) & 7
                if val == 0:
                    val = 8
                size = (instruction >> 6) & 3
                source = OpImmediate(SIZE_BYTE, val)
                dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                if extra_dest is None:
                    return error_value
                length = 2+extra_dest
        elif operation_code == 0x6:
            # Bcc/BSR/BRA
            if msb == 0x60:
                instr = 'bra'
            elif msb == 0x61:
                instr = 'bsr'
            else:
                instr = 'b'+Condition[(instruction >> 8) & 0xf]
            val = instruction & 0xff
            if val == 0:
                val = struct.unpack_from('>h', data, 2)[0]
                length = 4
            elif val == 0xff:
                val = struct.unpack_from('>L', data, 2)[0]
                length = 6
            else:
                if val & 0x80:
                    val -= 256
                length = 2
            dest = OpRegisterIndirectDisplacement(SIZE_LONG, 'pc', val)
        elif operation_code == 0x7:
            # MOVEQ
            instr = 'moveq'
            size = SIZE_LONG
            val = instruction & 0xff
            if val & 0x80:
                val |= 0xffffff00
            source = OpImmediate(size, val)
            dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
            length = 2
        elif operation_code == 0x8:
            # OR/DIV/SBCD
            if instruction & 0xf0c0 == 0x80c0:
                if instruction & 0x0100:
                    instr = 'divs'
                else:
                    instr = 'divu'
                size = SIZE_WORD
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                if extra_source is None:
                    return error_value
                length = 2+extra_source
            elif instruction & 0xf1f0 == 0x8100:
                instr = 'sbcd'
                length = 2
                dest = OpRegisterDirect(SIZE_BYTE, Registers[(instruction >> 9) & 7])
                source = OpRegisterDirect(SIZE_BYTE, Registers[instruction & 7])
                if instruction & 8:
                    dest = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[((instruction >> 9) & 7) + 8])
                    source = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[(instruction & 7) + 8])
            elif instruction & 0xf130 == 0x8100:
                if instruction & 0x0040:
                    instr = 'pack'
                    if instruction & 8:
                        dest = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[((instruction >> 9) & 7) + 8])
                        source = OpRegisterIndirectPredecrement(SIZE_WORD, Registers[(instruction & 7) + 8])
                    else:
                        dest = OpRegisterDirect(SIZE_BYTE, Registers[(instruction >> 9) & 7])
                        source = OpRegisterDirect(SIZE_WORD, Registers[instruction & 7])
                else:
                    instr = 'unpk'
                    if instruction & 8:
                        dest = OpRegisterIndirectPredecrement(SIZE_WORD, Registers[((instruction >> 9) & 7) + 8])
                        source = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[(instruction & 7) + 8])
                    else:
                        dest = OpRegisterDirect(SIZE_WORD, Registers[(instruction >> 9) & 7])
                        source = OpRegisterDirect(SIZE_BYTE, Registers[instruction & 7])
                length = 4
                third = OpImmediate(SIZE_WORD, struct.unpack_from(">H", data, 2)[0])
            else:
                instr = 'or'
                opmode = (instruction >> 6) & 0x7
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                if opmode & 4:
                    source, dest = dest, source
                if extra_source is None:
                    return error_value
                length = 2+extra_source
        elif operation_code == 0x9:
            # SUB/SUBA/SUBX
            instr = 'sub'
            opmode = (instruction >> 6) & 0x7
            if opmode in (0x03, 0x07):
                instr = 'suba'
                if opmode == 0x03:
                    size = SIZE_WORD
                else:
                    size = SIZE_LONG
                dest = OpRegisterDirect(SIZE_LONG, Registers[((instruction >> 9) & 7) + 8])
            else:
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
            source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
            if instr == 'sub' and opmode & 4:
                if isinstance(source, OpRegisterDirect):
                    instr = 'subx'
                    if source.reg[0] == 'a' or source.reg == 'sp':
                        source = OpRegisterIndirectPredecrement(size, source.reg)
                        dest = OpRegisterIndirectPredecrement(size, dest.reg)
                else:
                    source, dest = dest, source
            if extra_source is None:
                return error_value
            length = 2+extra_source
        elif operation_code == 0xa:
            # (unassigned, reserved)
            pass
        elif operation_code == 0xb:
            # CMP/EOR
            instr = 'cmp'
            opmode = (instruction >> 6) & 0x7
            if opmode in (0x03, 0x07):
                instr = 'cmpa'
                if opmode == 0x03:
                    size = SIZE_WORD
                else:
                    size = SIZE_LONG
                dest = OpRegisterDirect(size, Registers[((instruction >> 9) & 7) + 8])
            else:
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
            source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
            if instr == 'cmp' and opmode & 4:
                if instruction & 0x0038 == 0x0008:
                    instr = 'cmpm'
                    source = OpRegisterIndirectPostincrement(size, Registers[instruction & 15])
                    dest = OpRegisterIndirectPostincrement(size, Registers[((instruction >> 9) & 7) + 8])
                else:
                    source, dest = dest, source
                    instr = 'eor'
            if extra_source is None:
                return error_value
            length = 2+extra_source
        elif operation_code == 0xc:
            # AND/MUL/ABCD/EXG
            if instruction & 0xf0c0 == 0xc0c0:
                if instruction & 0x0100:
                    instr = 'muls'
                else:
                    instr = 'mulu'
                size = SIZE_WORD
                source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                if extra_source is None:
                    return error_value
                length = 2+extra_source
            elif instruction & 0xf130 == 0xc100:
                if instruction & 0xf1f0 == 0xc100:
                    instr = 'abcd'
                    if instruction & 0x0008:
                        source = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[(instruction & 7) + 8])
                        dest = OpRegisterIndirectPredecrement(SIZE_BYTE, Registers[((instruction >> 9) & 7) + 8])
                    else:
                        source = OpRegisterDirect(SIZE_BYTE, Registers[instruction & 7])
                        dest = OpRegisterDirect(SIZE_BYTE, Registers[(instruction >> 9) & 7])
                else:
                    instr = 'exg'
                    size = SIZE_LONG
                    source = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                    dest = OpRegisterDirect(size, Registers[instruction & 7])
                    if instruction & 0xf1f8 == 0xc148:
                        source = OpRegisterIndirectPredecrement(size, Registers[((instruction >> 9) & 7) + 8])
                        dest = OpRegisterIndirectPredecrement(size, Registers[(instruction & 7) + 8])
                    if instruction & 0xf1f8 == 0xc188:
                        dest = OpRegisterIndirectPredecrement(size, Registers[(instruction & 7) + 8])
                length = 2
            else:
                instr = 'and'
                opmode = (instruction >> 6) & 0x7
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
                source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                if opmode & 4:
                    source, dest = dest, source
                if extra_source is None:
                    return error_value
                length = 2+extra_source
        elif operation_code == 0xd:
            # ADD/ADDA/ADDX
            instr = 'add'
            opmode = (instruction >> 6) & 0x7
            if opmode in (0x03, 0x07):
                instr = 'adda'
                if opmode == 0x03:
                    size = SIZE_WORD
                else:
                    size = SIZE_LONG
                dest = OpRegisterDirect(SIZE_LONG, Registers[((instruction >> 9) & 7) + 8])
            else:
                size = (instruction >> 6) & 3
                dest = OpRegisterDirect(size, Registers[(instruction >> 9) & 7])
            source, extra_source = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
            if instr == 'add' and opmode & 4:
                if isinstance(source, OpRegisterDirect):
                    instr = 'addx'
                    if source.reg[0] == 'a' or source.reg == 'sp':
                        source = OpRegisterIndirectPredecrement(size, source.reg)
                        dest = OpRegisterIndirectPredecrement(size, dest.reg)
                else:
                    source, dest = dest, source
            if extra_source is None:
                return error_value
            length = 2+extra_source
        elif operation_code == 0xe:
            # shift/rotate/bit field
            if instruction & 0xF8C0 == 0xE0C0:
                # shift/rotate
                size = SIZE_WORD
                direction = (instruction >> 8) & 1
                style = (instruction >> 9) & 3
                dest, extra_dest = self.decode_effective_address(instruction >> 3, instruction, data[2:], size)
                instr = ShiftStyle[style]
                if direction:
                    instr += 'l'
                else:
                    instr += 'r'
                if extra_dest is None:
                    return error_value
                length = 2+extra_dest
            elif instruction & 0xF8C0 == 0xE8C0:
                # bit field instructions
                # TODO
                style = (instruction >> 8) & 0x7
                instr = 'bf'+BitfieldStyle[style]
                length = 4
            else:
                # shift/rotate
                size = (instruction >> 6) & 3
                direction = (instruction >> 8) & 1
                style = (instruction >> 3) & 3
                if (instruction >> 5) & 1:
                    source = OpRegisterDirect(SIZE_LONG, Registers[(instruction >> 9) & 7])
                else:
                    val = (instruction >> 9) & 7
                    if val == 0:
                        val = 8
                    source = OpImmediate(SIZE_BYTE, val)
                dest = OpRegisterDirect(size, Registers[instruction & 7])
                instr = ShiftStyle[style]
                if direction:
                    instr += 'l'
                else:
                    instr += 'r'
                length = 2
        elif operation_code == 0xf:
            if instruction & 0xff20 == 0xf420:
                instr = 'cpush'
                length = 2
            elif instruction & 0xff80 == 0xff80:
                instruction = 'illFF'
                length = 2
            # coprocessor instructions
            # TODO
        if instr is None:
            # FIXME uncomment to debug
            #log_error('Bad opcode at 0x{:x}'.format(addr))
            return error_value

        #print((instr, length, size, source, dest, third))
        return instr, length, size, source, dest, third

