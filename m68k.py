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

import binaryninja

from typing import List, Optional, Tuple

import struct
import traceback
import os

from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP, LowLevelILFunction, ExpressionIndex
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import AddressField, ChoiceField, get_form_input
from binaryninja.types import Symbol
from binaryninja.enums import (Endianness, BranchType, InstructionTextTokenType,
        LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag,
        ImplicitRegisterExtend, SymbolType)
from binaryninja import BinaryViewType, lowlevelil

from .logging import log_debug
from .m68k_ops import *
from .m68k_disasm import *

ConditionMapping = {
    'hi': LowLevelILFlagCondition.LLFC_UGT, # unsigned greater than
    'ls': LowLevelILFlagCondition.LLFC_ULE, # unsigned less than or equal
    'cc': LowLevelILFlagCondition.LLFC_UGE, # unsigned greater than or equal
    'cs': LowLevelILFlagCondition.LLFC_ULT, # unsigned less than
    'ne': LowLevelILFlagCondition.LLFC_NE,  # not equal
    'eq': LowLevelILFlagCondition.LLFC_E,   # equal
    'vc': LowLevelILFlagCondition.LLFC_NO,  # no overflow
    'vs': LowLevelILFlagCondition.LLFC_O,   # overflow
    'pl': LowLevelILFlagCondition.LLFC_POS, # positive
    'mi': LowLevelILFlagCondition.LLFC_NEG, # negative
    'ge': LowLevelILFlagCondition.LLFC_SGE, # signed greater than or equal
    'lt': LowLevelILFlagCondition.LLFC_SLT, # signed less than
    'gt': LowLevelILFlagCondition.LLFC_SGT, # signed greater than or equal
    'le': LowLevelILFlagCondition.LLFC_SLE, # signed less than or equal
}
FlagsRequiredForFlagCondition = {
    LowLevelILFlagCondition.LLFC_UGT: ['c', 'z'], # hi
    LowLevelILFlagCondition.LLFC_ULE: ['c', 'z'], # ls
    LowLevelILFlagCondition.LLFC_UGE: ['c'], # cs
    LowLevelILFlagCondition.LLFC_ULT: ['c'], # cs
    LowLevelILFlagCondition.LLFC_NE:  ['z'], # ne
    LowLevelILFlagCondition.LLFC_E:   ['z'], # eq
    LowLevelILFlagCondition.LLFC_NO:  ['v'], # vc
    LowLevelILFlagCondition.LLFC_O:   ['v'], # vs
    LowLevelILFlagCondition.LLFC_POS: ['n'], # pl
    LowLevelILFlagCondition.LLFC_NEG: ['n'], # mi
    LowLevelILFlagCondition.LLFC_SGE: ['n', 'v'], # ge
    LowLevelILFlagCondition.LLFC_SLT: ['n', 'v'], # lt
    LowLevelILFlagCondition.LLFC_SGT: ['n', 'v', 'z'], # gt
    LowLevelILFlagCondition.LLFC_SLE: ['n', 'v', 'z'], # le
}

# hack for programs that rely on flags not being modified after `rts`.
RTS_PASS_FLAGS = False

class M68000(Architecture):
    name = "M68000"
    address_size = 4
    default_int_size = 4
    max_instr_length = 22
    endianness = Endianness.BigEndian
    regs = {
        'd0':    RegisterInfo('d0', 4),
        'd1':    RegisterInfo('d1', 4),
        'd2':    RegisterInfo('d2', 4),
        'd3':    RegisterInfo('d3', 4),
        'd4':    RegisterInfo('d4', 4),
        'd5':    RegisterInfo('d5', 4),
        'd6':    RegisterInfo('d6', 4),
        'd7':    RegisterInfo('d7', 4),
        'a0':    RegisterInfo('a0', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a1':    RegisterInfo('a1', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a2':    RegisterInfo('a2', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a3':    RegisterInfo('a3', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a4':    RegisterInfo('a4', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a5':    RegisterInfo('a5', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'a6':    RegisterInfo('a6', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),
        'sp':    RegisterInfo('sp', 4, extend=ImplicitRegisterExtend.SignExtendToFullWidth),

        'd0.w':  RegisterInfo('d0', 2),
        'd1.w':  RegisterInfo('d1', 2),
        'd2.w':  RegisterInfo('d2', 2),
        'd3.w':  RegisterInfo('d3', 2),
        'd4.w':  RegisterInfo('d4', 2),
        'd5.w':  RegisterInfo('d5', 2),
        'd6.w':  RegisterInfo('d6', 2),
        'd7.w':  RegisterInfo('d7', 2),
        'd0.b':  RegisterInfo('d0', 1),
        'd1.b':  RegisterInfo('d1', 1),
        'd2.b':  RegisterInfo('d2', 1),
        'd3.b':  RegisterInfo('d3', 1),
        'd4.b':  RegisterInfo('d4', 1),
        'd5.b':  RegisterInfo('d5', 1),
        'd6.b':  RegisterInfo('d6', 1),
        'd7.b':  RegisterInfo('d7', 1),
        'a0.w':  RegisterInfo('a0', 2),
        'a1.w':  RegisterInfo('a1', 2),
        'a2.w':  RegisterInfo('a2', 2),
        'a3.w':  RegisterInfo('a3', 2),
        'a4.w':  RegisterInfo('a4', 2),
        'a5.w':  RegisterInfo('a5', 2),
        'a6.w':  RegisterInfo('a6', 2),
        'sp.w':  RegisterInfo('sp', 2),
        'a0.b':  RegisterInfo('a0', 1),
        'a1.b':  RegisterInfo('a1', 1),
        'a2.b':  RegisterInfo('a2', 1),
        'a3.b':  RegisterInfo('a3', 1),
        'a4.b':  RegisterInfo('a4', 1),
        'a5.b':  RegisterInfo('a5', 1),
        'a6.b':  RegisterInfo('a6', 1),
        'sp.b':  RegisterInfo('sp', 1),

        'sr':    RegisterInfo('sr', 2),
        'ccr':   RegisterInfo('sr', 1),

        # fake registers to return flags from subroutines
        'rn':    RegisterInfo('rn', 1),
        'rz':    RegisterInfo('rz', 1),
        'rv':    RegisterInfo('rv', 1),
        'rc':    RegisterInfo('rc', 1),

        # control registers
        # MC68010/MC68020/MC68030/MC68040/CPU32
        'sfc':   RegisterInfo('sfc', 4),
        'dfc':   RegisterInfo('dfc', 4),
        'usp':   RegisterInfo('usp', 4),
        'vbr':   RegisterInfo('vbr', 4),
        # MC68020/MC68030/MC68040
        'cacr':  RegisterInfo('cacr', 4),
        'caar':  RegisterInfo('caar', 4),
        'msp':   RegisterInfo('msp', 4),
        'isp':   RegisterInfo('isp', 4),
        # MC68040/MC68LC040
        'tc':    RegisterInfo('tc', 4),
        'itt0':  RegisterInfo('itt0', 4),
        'itt1':  RegisterInfo('itt1', 4),
        'dtt0':  RegisterInfo('dtt0', 4),
        'dtt1':  RegisterInfo('dtt1', 4),
        'mmusr': RegisterInfo('mmusr', 4),
        'urp':   RegisterInfo('urp', 4),
        'srp':   RegisterInfo('srp', 4),
        # MC68EC040
        'iacr0': RegisterInfo('iacr0', 4),
        'iacr1': RegisterInfo('iacr1', 4),
        'dacr0': RegisterInfo('dacr0', 4),
        'dacr1': RegisterInfo('dacr1', 4),
    }
    stack_pointer = 'sp'
    flags = ['x', 'n', 'z', 'v', 'c']
    flag_write_types = ['*', 'nzvc', 'nz']
    flags_written_by_flag_write_type = {
        '*': ['x', 'n', 'z', 'v', 'c'],
        'nzvc': ['n', 'z', 'v', 'c'],
        'nz': ['n', 'z'],
    }
    flag_roles = {
        'x': FlagRole.SpecialFlagRole,
        'n': FlagRole.NegativeSignFlagRole,
        'z': FlagRole.ZeroFlagRole,
        'v': FlagRole.OverflowFlagRole,
        'c': FlagRole.CarryFlagRole,
    }
    # condition mapping to LLIL flag conditions
    ConditionMapping = {
        'hi': LowLevelILFlagCondition.LLFC_UGT,
        'ls': LowLevelILFlagCondition.LLFC_ULE,
        'cc': LowLevelILFlagCondition.LLFC_UGE,
        'cs': LowLevelILFlagCondition.LLFC_ULT,
        'ne': LowLevelILFlagCondition.LLFC_NE,
        'eq': LowLevelILFlagCondition.LLFC_E,
        'vc': LowLevelILFlagCondition.LLFC_NO,
        'vs': LowLevelILFlagCondition.LLFC_O,
        'pl': LowLevelILFlagCondition.LLFC_POS,
        'mi': LowLevelILFlagCondition.LLFC_NEG,
        'ge': LowLevelILFlagCondition.LLFC_SGE,
        'lt': LowLevelILFlagCondition.LLFC_SLT,
        'gt': LowLevelILFlagCondition.LLFC_SGT,
        'le': LowLevelILFlagCondition.LLFC_SLE,
    }
    flags_required_for_flag_condition = FlagsRequiredForFlagCondition
    control_registers = {
    }
    memory_indirect = False
    movem_store_decremented = False

    def __init__(self):
        Architecture.__init__(self)
        self.disasm = M68KDisasm(self.address_size, self.control_registers)

    def generate_instruction_il(self, il: LowLevelILFunction, instr: str, length: int, size: int, source: Optional[Operand], dest: Optional[Operand], third: Optional[Operand]):
        size_bytes = None
        if size is not None:
            size_bytes = 1 << size

        if instr in ('move', 'moveq'):
            if instr == 'move' and isinstance(dest, OpRegisterDirect) and dest.reg in ('ccr', 'sr'):
                il.append(il.set_reg(1, LLIL_TEMP(0), source.get_source_il(il)))
                il.append(il.set_flag('c', il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x01))))
                il.append(il.set_flag('v', il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x02))))
                il.append(il.set_flag('z', il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x04))))
                il.append(il.set_flag('n', il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x08))))
                il.append(il.set_flag('x', il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x10))))
            else:
                flags = 'nzvc'
                if ((isinstance(source, OpRegisterDirect) and source.reg in ('usp', 'ccr', 'sr')) or
                    (isinstance(dest, OpRegisterDirect) and dest.reg in ('usp', 'ccr', 'sr'))):
                    # move to/from control registers do not set flags
                    flags = 0
                il.append(
                    dest.get_dest_il(il,
                        source.get_source_il(il),
                        flags
                    )
                )
        elif instr in ('movea', 'movec'):
            # dest.size = SIZE_LONG
            # il.append(
            #     dest.get_dest_il(il,
            #         il.sign_extend(4,
            #             source.get_source_il(il)
            #         )
            #     )
            # )
            il.append(
                dest.get_dest_il(il,
                    source.get_source_il(il)
                )
            )
        elif instr == 'clr':
            il.append(
                dest.get_dest_il(il,
                    il.const(4, 0),
                    'nzvc'
                )
            )
        elif instr in ('add', 'addi', 'addq'):
            il.append(
                dest.get_dest_il(il,
                    il.add(size_bytes,
                        dest.get_source_il(il),
                        source.get_source_il(il),
                        flags='*'
                    )
                )
            )
        elif instr == 'adda':
            dest.size = SIZE_LONG
            il.append(
                dest.get_dest_il(il,
                    il.add(4,
                        dest.get_source_il(il),
                        il.sign_extend(4,
                            source.get_source_il(il)
                        )
                    )
                )
            )
        elif instr == 'addx':
            il.append(
                dest.get_dest_il(il,
                    il.add(size_bytes,
                        il.add(size_bytes,
                            dest.get_source_il(il),
                            source.get_source_il(il),
                            flags='*'
                        ),
                        il.flag('x'),
                        flags='*'
                    )
                )
            )
        elif instr in ('sub', 'subi', 'subq'):
            il.append(
                dest.get_dest_il(il,
                    il.sub(size_bytes,
                        dest.get_source_il(il),
                        source.get_source_il(il),
                        flags='*'
                    )
                )
            )
        elif instr == 'suba':
            dest.size = SIZE_LONG
            il.append(
                dest.get_dest_il(il,
                    il.sub(4,
                        dest.get_source_il(il),
                        il.sign_extend(4,
                            source.get_source_il(il)
                        )
                    )
                )
            )
        elif instr == 'subx':
            il.append(
                dest.get_dest_il(il,
                    il.sub(size_bytes,
                        il.sub(size_bytes,
                            dest.get_source_il(il),
                            source.get_source_il(il),
                            flags='*'
                        ),
                        il.flag('x'),
                        flags='*'
                    )
                )
            )
        elif instr == 'neg':
            il.append(
                dest.get_dest_il(il,
                    il.neg_expr(size_bytes,
                        dest.get_source_il(il),
                        flags='*'
                    )
                )
            )
        elif instr == 'negx':
            il.append(
                dest.get_dest_il(il,
                    il.sub(size_bytes,
                        il.neg_expr(size_bytes,
                            dest.get_source_il(il),
                            flags='*'
                        ),
                        il.flag('x'),
                        flags='*'
                    )
                )
            )
        elif instr == 'abcd':
            # TODO
            il.append(il.unimplemented())
        elif instr == 'sbcd':
            # TODO
            il.append(il.unimplemented())
        elif instr == 'nbcd':
            # TODO
            il.append(il.unimplemented())
        elif instr == 'pack':
            il.append(
                il.set_reg(2,
                    LLIL_TEMP(0),
                    il.add(2,
                        source.get_source_il(il),
                        third.get_source_il(il)
                    )
                )
            )
            il.append(
                dest.get_dest_il(il,
                    il.or_expr(1,
                        il.and_expr(2,
                            il.reg(2, LLIL_TEMP(0)),
                            il.const(2, 0x000F)
                        ),
                        il.logical_shift_right(2,
                            il.and_expr(2,
                                il.reg(2, LLIL_TEMP(0)),
                                il.const(2, 0x0F00)
                            ),
                            il.const(1, 4)
                        )
                    )
                )
            )
        elif instr == 'unpk':
            il.append(
                il.set_reg(1,
                    LLIL_TEMP(0),
                    source.get_source_il(il)
                )
            )
            il.append(
                dest.get_dest_il(il,
                    il.add(2,
                        il.or_expr(2,
                            il.and_expr(2,
                                il.reg(1, LLIL_TEMP(0)),
                                il.const(1, 0x0F)
                            ),
                            il.shift_left(2,
                                il.and_expr(2,
                                    il.reg(1, LLIL_TEMP(0)),
                                    il.const(1, 0xF0)
                                ),
                                il.const(1, 4)
                            )
                        ),
                        third.get_source_il(il)
                    )
                )
            )
        elif instr in ('muls', 'mulu'):
            if isinstance(dest, OpRegisterDirectPair):
                log_debug(instr, 'FIXME')
                il.append(
                    il.set_reg_split(4,
                        dest.reg1,
                        dest.reg2,
                        il.mult(4,
                            source.get_source_il(il),
                            # FIXME
                            dest.get_source_il(il)[0],
                            flags='nzvc'
                        )
                    )
                )
            else:
                il.append(
                    il.set_reg(4,
                        dest.reg,
                        il.mult(4,
                            source.get_source_il(il),
                            dest.get_source_il(il),
                            flags='nzvc'
                        )
                    )
                )
        elif instr == 'divs':
            if size == 1:
                dividend_il = dest.get_source_il(il)
                divisor_il = source.get_source_il(il)
                dest.size = SIZE_LONG
                il.append(
                    dest.get_dest_il(il,
                        il.or_expr(4,
                            il.shift_left(4, il.mod_signed(2, dividend_il, divisor_il), il.const(1, 16)),
                            il.div_signed(2, dividend_il, divisor_il, flags='nzvc')
                        )
                    )
                )
            elif isinstance(dest, OpRegisterDirect):
                dividend_il = dest.get_source_il(il)
                divisor_il = source.get_source_il(il)
                il.append(
                    dest.get_dest_il(il,
                        il.div_signed(4, dividend_il, divisor_il, flags='nzvc')
                    )
                )
            else:
                dividend_il = il.or_expr(8, il.shift_left(8, il.reg(4, dest.reg1), il.const(1, 32)), il.reg(4, dest.reg2))
                divisor_il = source.get_source_il(il)
                il.append(
                    il.set_reg(4,
                        LLIL_TEMP(0),
                        il.mod_signed(4, dividend_il, divisor_il)
                    )
                )
                il.append(
                    il.set_reg(4,
                        dest.reg2,
                        il.div_signed(4, dividend_il, divisor_il, flags='nzvc')
                    )
                )
                il.append(
                    il.set_reg(4,
                        dest.reg1,
                        il.reg(4, LLIL_TEMP(0))
                    )
                )
        elif instr == 'divsl':
            dividend_il = il.reg(4, dest.reg2)
            divisor_il = source.get_source_il(il)
            il.append(
                il.set_reg(4,
                    dest.reg1,
                    il.mod_signed(4, dividend_il, divisor_il)
                )
            )
            il.append(
                il.set_reg(4,
                    dest.reg2,
                    il.div_signed(4, dividend_il, divisor_il, flags='nzvc')
                )
            )
        elif instr == 'divu':
            if size == 1:
                dividend_il = dest.get_source_il(il)
                divisor_il = source.get_source_il(il)
                dest.size = SIZE_LONG
                il.append(
                    dest.get_dest_il(il,
                        il.or_expr(4,
                            il.shift_left(4, il.mod_unsigned(2, dividend_il, divisor_il), il.const(1, 16)),
                            il.div_unsigned(2, dividend_il, divisor_il, flags='nzvc')
                        )
                    )
                )
            elif isinstance(dest, OpRegisterDirect):
                dividend_il = dest.get_source_il(il)
                divisor_il = source.get_source_il(il)
                il.append(
                    dest.get_dest_il(il,
                        il.div_unsigned(4, dividend_il, divisor_il, flags='nzvc')
                    )
                )
            else:
                dividend_il = il.or_expr(8, il.shift_left(8, il.reg(4, dest.reg1), il.const(1, 32)), il.reg(4, dest.reg2))
                divisor_il = source.get_source_il(il)
                il.append(
                    il.set_reg(4,
                        LLIL_TEMP(0),
                        il.mod_unsigned(4, dividend_il, divisor_il)
                    )
                )
                il.append(
                    il.set_reg(4,
                        dest.reg2,
                        il.div_unsigned(4, dividend_il, divisor_il, flags='nzvc')
                    )
                )
                il.append(
                    il.set_reg(4,
                        dest.reg1,
                        il.reg(4, LLIL_TEMP(0))
                    )
                )
        elif instr == 'divul':
            dividend_il = il.reg(4, dest.reg2)
            divisor_il = source.get_source_il(il)
            il.append(
                il.set_reg(4,
                    dest.reg1,
                    il.mod_unsigned(4, dividend_il, divisor_il)
                )
            )
            il.append(
                il.set_reg(4,
                    dest.reg2,
                    il.div_unsigned(4, dividend_il, divisor_il, flags='nzvc')
                )
            )
        elif instr == 'cas':
            skip_label_found = True

            skip = il.get_label_for_address(il.arch, il.current_address+length)

            if skip is None:
                skip = LowLevelILLabel()
                skip_label_found = False

            il.append(
                il.sub(size_bytes,
                    third.get_source_il(il),
                    source.get_source_il(il),
                    flags='nzvc'
                )
            )

            equal = LowLevelILLabel()
            not_equal = LowLevelILLabel()

            il.append(
                il.if_expr(il.flag_condition(LowLevelILFlagCondition.LLFC_E), equal, not_equal)
            )

            il.mark_label(equal)

            il.append(
                third.get_dest_il(il,
                    dest.get_source_il(il)
                )
            )

            il.append(
                il.goto(skip)
            )

            il.mark_label(not_equal)

            il.append(
                source.get_dest_il(il,
                    third.get_source_il(il)
                )
            )

            if not skip_label_found:
                il.mark_label(skip)
        elif instr == 'cas2':
            skip_label_found = True

            skip = il.get_label_for_address(il.arch, il.current_address+length)

            if skip is None:
                skip = LowLevelILLabel()
                skip_label_found = False

            log_debug(instr, 'FIXME')
            il.append(
                il.sub(size_bytes,
                    # FIXME
                    third.get_source_il(il)[0],
                    source.get_source_il(il)[0],
                    flags='nzvc'
                )
            )

            equal = LowLevelILLabel()
            not_equal = LowLevelILLabel()
            check2 = LowLevelILLabel()

            il.append(
                il.if_expr(il.flag_condition(LowLevelILFlagCondition.LLFC_E), check2, not_equal)
            )

            il.mark_label(check2)

            log_debug(instr, 'FIXME')
            il.append(
                il.sub(size_bytes,
                    # FIXME
                    third.get_source_il(il)[1],
                    source.get_source_il(il)[1],
                    flags='nzvc'
                )
            )

            il.append(
                il.if_expr(il.flag_condition(LowLevelILFlagCondition.LLFC_E), equal, not_equal)
            )

            il.mark_label(equal)

            for it in third.get_dest_il(il,
                        dest.get_source_il(il)
                    ):
                il.append(it)

            il.append(
                il.goto(skip)
            )

            il.mark_label(not_equal)

            for it in source.get_dest_il(il,
                        third.get_source_il(il)
                    ):
                il.append(it)

            il.append(
                il.goto(skip)
            )

            if not skip_label_found:
                il.mark_label(skip)
        elif instr == 'chk':
            skip_label_found = True

            skip = il.get_label_for_address(il.arch, il.current_address+length)

            if skip is None:
                skip = LowLevelILLabel()
                skip_label_found = False

            trap = LowLevelILLabel()
            check = LowLevelILLabel()

            il.append(
                il.if_expr(
                    il.compare_unsigned_less_than(size_bytes,
                        dest.get_source_il(il),
                        il.const(size_bytes, 0)
                    ),
                    trap,
                    check
                )
            )

            il.mark_label(check)

            il.append(
                il.if_expr(
                    il.compare_unsigned_greater_than(size_bytes,
                        dest.get_source_il(il),
                        source.get_source_il(il)
                    ),
                    trap,
                    skip
                )
            )

            il.mark_label(trap)

            il.append(
                il.system_call()
            )

            il.append(
                il.goto(skip)
            )

            if not skip_label_found:
                il.mark_label(skip)
        elif instr == 'chk2':
            skip_label_found = True

            skip = il.get_label_for_address(il.arch, il.current_address+length)

            if skip is None:
                skip = LowLevelILLabel()
                skip_label_found = False

            trap = LowLevelILLabel()
            check = LowLevelILLabel()

            il.append(
                il.set_reg(4,
                    LLIL_TEMP(0),
                    source.get_address_il(il)
                )
            )

            il.append(
                il.if_expr(
                    il.compare_unsigned_less_than(size_bytes,
                        dest.get_source_il(il),
                        il.load(size_bytes,
                            il.reg(4, LLIL_TEMP(0))
                        )
                    ),
                    trap,
                    check
                )
            )

            il.mark_label(check)

            il.append(
                il.if_expr(
                    il.compare_unsigned_greater_than(size_bytes,
                        dest.get_source_il(il),
                        il.load(size_bytes,
                            il.add(4,
                                il.reg(4, LLIL_TEMP(0)),
                                il.const(4, size_bytes)
                            )
                        )
                    ),
                    trap,
                    skip
                )
            )

            il.mark_label(trap)

            il.append(
                il.system_call()
            )

            il.append(
                il.goto(skip)
            )

            if not skip_label_found:
                il.mark_label(skip)
        elif instr == 'bchg':
            bit_number_il = il.mod_unsigned(1,
                source.get_source_il(il),
                il.const(1, 8 << dest.size)
            )
            il.append(
                il.set_flag('z',
                    il.compare_not_equal(4,
                        il.test_bit(4,
                            dest.get_source_il(il),
                            il.shift_left(4,
                                il.const(4, 1),
                                bit_number_il
                            )
                        ),
                        il.const(4, 0)
                    )
                )
            )
            il.append(
                dest.get_dest_il(il,
                    il.xor_expr(4,
                        dest.get_source_il(il),
                        il.shift_left(4,
                            il.const(4, 1),
                            bit_number_il
                        )
                    )
                )
            )
        elif instr == 'bclr':
            bit_number_il = il.mod_unsigned(1,
                source.get_source_il(il),
                il.const(1, 8 << dest.size)
            )
            il.append(
                il.set_flag('z',
                    il.compare_not_equal(4,
                        il.test_bit(4,
                            dest.get_source_il(il),
                            il.shift_left(4,
                                il.const(4, 1),
                                bit_number_il
                            )
                        ),
                        il.const(4, 0)
                    )
                )
            )
            il.append(
                dest.get_dest_il(il,
                    il.and_expr(4,
                        dest.get_source_il(il),
                        il.not_expr(4,
                            il.shift_left(4,
                                il.const(4, 1),
                                bit_number_il
                            )
                        )
                    )
                )
            )
        elif instr == 'bset':
            bit_number_il = il.mod_unsigned(1,
                source.get_source_il(il),
                il.const(1, 8 << dest.size)
            )
            il.append(
                il.set_flag('z',
                    il.compare_not_equal(4,
                        il.test_bit(4,
                            dest.get_source_il(il),
                            il.shift_left(4,
                                il.const(4, 1),
                                bit_number_il
                            )
                        ),
                        il.const(4, 0)
                    )
                )
            )
            il.append(
                dest.get_dest_il(il,
                    il.or_expr(4,
                        dest.get_source_il(il),
                        il.shift_left(4,
                            il.const(4, 1),
                            bit_number_il
                        )
                    )
                )
            )
        elif instr == 'btst':
            bit_number_il = il.mod_unsigned(1,
                source.get_source_il(il),
                il.const(1, 8 << dest.size)
            )
            il.append(
                il.set_flag('z',
                    il.compare_not_equal(4,
                        il.test_bit(4,
                            dest.get_source_il(il),
                            il.shift_left(4,
                                il.const(4, 1),
                                bit_number_il
                            )
                        ),
                        il.const(4, 0)
                    )
                )
            )
        elif instr in ('asl', 'lsl'):
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.shift_left(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        flags='*'
                    )
                )
            )
        elif instr == 'asr':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.arith_shift_right(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        flags='*'
                    )
                )
            )
        elif instr == 'lsr':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.logical_shift_right(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        flags='*'
                    )
                )
            )
        elif instr == 'rol':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.rotate_left(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        flags='*'
                    )
                )
            )
        elif instr == 'ror':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.rotate_right(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        flags='*'
                    )
                )
            )
        elif instr == 'roxl':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.rotate_left_carry(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        il.flag('x'),
                        flags='*'
                    )
                )
            )
        elif instr == 'roxr':
            source_il = il.const(1, 1)
            if source is not None:
                source_il = source.get_source_il(il)
            il.append(
                dest.get_dest_il(il,
                    il.rotate_right_carry(size_bytes,
                        dest.get_source_il(il),
                        source_il,
                        il.flag('x'),
                        flags='*'
                    )
                )
            )
        elif instr in ('cmp', 'cmpi', 'cmpm'):
            il.append(
                il.sub(size_bytes,
                    dest.get_source_il(il),
                    source.get_source_il(il),
                    flags='nzvc'
                )
            )
        elif instr == 'cmpa':
            dest.size = SIZE_LONG
            il.append(
                il.sub(4,
                    dest.get_source_il(il),
                    il.sign_extend(4,
                        source.get_source_il(il)
                    ),
                    flags='nzvc'
                )
            )
        elif instr == 'cmp2':
            skip_label_found = True

            skip = il.get_label_for_address(il.arch, il.current_address+length)

            if skip is None:
                skip = LowLevelILLabel()
                skip_label_found = False

            check = LowLevelILLabel()

            il.append(
                il.set_reg(4,
                    LLIL_TEMP(0),
                    source.get_address_il(il)
                )
            )

            il.append(
                il.sub(size_bytes,
                    dest.get_source_il(il),
                    il.load(size_bytes,
                        il.reg(4, LLIL_TEMP(0))
                    ),
                    flags='nzvc'
                )
            )

            il.append(
                il.if_expr(
                    il.flag_condition(LowLevelILFlagCondition.LLFC_ULT),
                    skip,
                    check
                )
            )

            il.mark_label(check)

            il.append(
                il.sub(size_bytes,
                    dest.get_source_il(il),
                    il.load(size_bytes,
                        il.add(4,
                            il.reg(4, LLIL_TEMP(0)),
                            il.const(4, size_bytes)
                        )
                    ),
                    flags='nzvc'
                )
            )

            il.append(
                il.goto(skip)
            )

            if not skip_label_found:
                il.mark_label(skip)
        elif instr == 'tas':
            il.append(
                il.set_reg(1, LLIL_TEMP(0), dest.get_source_il(il), flags='nzvc')
            )
            il.append(
                dest.get_dest_il(il,
                    il.or_expr(1,
                        il.reg(1, LLIL_TEMP(0)),
                        il.const(1, 0x80)
                    )
                )
            )
        elif instr == 'tst':
            il.append(
                il.sub(size_bytes,
                    dest.get_source_il(il),
                    il.const(size_bytes, 0),
                    flags='nz'
                )
            )
            # vc: always cleared
            il.append(il.set_flag('v', il.const(1, 0x0)))
            il.append(il.set_flag('c', il.const(1, 0x0)))
        elif instr in ('and', 'andi'):
            if instr == 'andi' and isinstance(dest, OpRegisterDirect) and dest.reg in ('ccr', 'sr'):
                if not source.value & 0x01: il.append(il.set_flag('c', il.const(1, 0)))
                if not source.value & 0x02: il.append(il.set_flag('v', il.const(1, 0)))
                if not source.value & 0x04: il.append(il.set_flag('z', il.const(1, 0)))
                if not source.value & 0x08: il.append(il.set_flag('n', il.const(1, 0)))
                if not source.value & 0x11: il.append(il.set_flag('x', il.const(1, 0)))
            else:
                il.append(
                    dest.get_dest_il(il,
                        il.and_expr(size_bytes,
                            dest.get_source_il(il),
                            source.get_source_il(il),
                            flags='nzvc'
                        )
                    )
                )
        elif instr in ('or', 'ori'):
            if instr == 'ori' and isinstance(dest, OpRegisterDirect) and dest.reg in ('ccr', 'sr'):
                if source.value & 0x01: il.append(il.set_flag('c', il.const(1, 1)))
                if source.value & 0x02: il.append(il.set_flag('v', il.const(1, 1)))
                if source.value & 0x04: il.append(il.set_flag('z', il.const(1, 1)))
                if source.value & 0x08: il.append(il.set_flag('n', il.const(1, 1)))
                if source.value & 0x11: il.append(il.set_flag('x', il.const(1, 1)))
            else:
                il.append(
                    dest.get_dest_il(il,
                        il.or_expr(size_bytes,
                            dest.get_source_il(il),
                            source.get_source_il(il),
                            flags='nzvc'
                        )
                    )
                )
        elif instr in ('eor', 'eori'):
            if instr == 'eori' and isinstance(dest, OpRegisterDirect) and dest.reg in ('ccr', 'sr'):
                if source.value & 0x01: il.append(il.set_flag('c', il.xor_expr(1, il.flag('c'), il.const(1, 1))))
                if source.value & 0x02: il.append(il.set_flag('v', il.xor_expr(1, il.flag('v'), il.const(1, 1))))
                if source.value & 0x04: il.append(il.set_flag('z', il.xor_expr(1, il.flag('z'), il.const(1, 1))))
                if source.value & 0x08: il.append(il.set_flag('n', il.xor_expr(1, il.flag('n'), il.const(1, 1))))
                if source.value & 0x11: il.append(il.set_flag('x', il.xor_expr(1, il.flag('x'), il.const(1, 1))))
            else:
                il.append(
                    dest.get_dest_il(il,
                        il.xor_expr(size_bytes,
                            dest.get_source_il(il),
                            source.get_source_il(il),
                            flags='nzvc'
                        )
                    )
                )
        elif instr == 'not':
            il.append(
                dest.get_dest_il(il,
                    il.not_expr(size_bytes,
                        dest.get_source_il(il),
                        flags='nzvc'
                    )
                )
            )
        elif instr == 'swap':
            il.append(
                dest.get_dest_il(il,
                    il.rotate_right(4,
                        dest.get_source_il(il),
                        il.const(1, 16)
                    )
                )
            )
        elif instr == 'exg':
            il.append(
                il.set_reg(4, LLIL_TEMP(0), source.get_source_il(il))
            )
            il.append(
                source.get_dest_il(il, dest.get_source_il(il))
            )
            il.append(
                dest.get_dest_il(il, il.reg(4, LLIL_TEMP(0)))
            )
        elif instr == 'ext':
            if not dest:
                il.append(il.unimplemented())
            elif dest.size == 1:
                il.append(
                    il.set_reg(2,
                        dest.reg,
                        il.sign_extend(4,
                            il.reg(1, dest.reg),
                            flags='nzvc'
                        )
                    )
                )
            else:
                il.append(
                    il.set_reg(4,
                        dest.reg,
                        il.sign_extend(4,
                            il.reg(2, dest.reg),
                            flags='nzvc'
                        )
                    )
                )
        elif instr == 'extb':
            reg = dest.reg
            il.append(
                il.set_reg(4,
                    reg,
                    il.sign_extend(4,
                        il.reg(1, reg),
                        flags='nzvc'
                    )
                )
            )
        elif instr == 'movem':
            if isinstance(source, OpRegisterMovemList):
                if isinstance(dest, OpRegisterIndirectPredecrement):
                    il.append(
                        il.set_reg(4, LLIL_TEMP(0), dest.get_address_il(il))
                    )
                    if self.movem_store_decremented:
                        il.append(
                            il.set_reg(4,
                                dest.reg,
                                il.sub(4,
                                    il.reg(4, LLIL_TEMP(0)),
                                    il.const(4, len(source.regs)*size_bytes)
                                )
                            )
                        )
                    for k in range(len(source.regs)):
                        il.append(
                            il.store(size_bytes,
                                il.sub(4,
                                    il.reg(4, LLIL_TEMP(0)),
                                    il.const(4, (k+1)*size_bytes)
                                ),
                                il.reg(size_bytes, source.regs[len(source.regs)-1-k])
                            )
                        )
                    if not self.movem_store_decremented:
                        il.append(
                            il.set_reg(4,
                                dest.reg,
                                il.sub(4,
                                    il.reg(4, LLIL_TEMP(0)),
                                    il.const(4, len(source.regs)*size_bytes)
                                )
                            )
                        )
                else:
                    il.append(
                        il.set_reg(4, LLIL_TEMP(0), dest.get_address_il(il))
                    )
                    for k in range(len(source.regs)):
                        il.append(
                            il.store(size_bytes,
                                il.add(4,
                                    il.reg(4, LLIL_TEMP(0)),
                                    il.const(4, k*size_bytes)
                                ),
                                il.reg(size_bytes, source.regs[k])
                            )
                        )
            else:
                il.append(
                    il.set_reg(4, LLIL_TEMP(0), source.get_address_il(il))
                )
                for k in range(len(dest.regs)):
                    il.append(
                        il.set_reg(size_bytes,
                            dest.regs[k],
                            il.load(size_bytes,
                                il.add(4,
                                    il.reg(4, LLIL_TEMP(0)),
                                    il.const(4, k*size_bytes)
                                )
                            )
                        )
                    )
                if isinstance(source, OpRegisterIndirectPostincrement):
                    il.append(
                        il.set_reg(4,
                            source.reg,
                            il.add(4,
                                il.reg(4, LLIL_TEMP(0)),
                                il.const(4, len(dest.regs)*size_bytes)
                            )
                        )
                    )
        elif instr == 'lea':
            il.append(
                dest.get_dest_il(il, source.get_address_il(il))
            )
        elif instr == 'pea':
            il.append(
                il.push(4, dest.get_address_il(il))
            )
        elif instr == 'link':
            source.size = SIZE_LONG
            il.append(
                il.push(4, source.get_source_il(il))
            )
            il.append(
                source.get_dest_il(il, il.reg(4, "sp"))
            )
            il.append(
                il.set_reg(4,
                    "sp",
                    il.add(4,
                        il.reg(4, "sp"),
                        il.sign_extend(4, dest.get_source_il(il))
                    )
                )
            )
        elif instr == 'unlk':
            il.append(
                il.set_reg(4, "sp", source.get_source_il(il))
            )
            il.append(
                source.get_dest_il(il, il.pop(4))
            )
        elif instr in ('jmp', 'bra'):
            tmpil = LowLevelILFunction(il.arch)
            _dest_il = dest.get_address_il2(tmpil)
            dest_il = _dest_il[0]
            for i in _dest_il[1]:
                tmpil.append(i)

            dstlabel = None
            try:
                if tmpil[dest_il].operation == LowLevelILOperation.LLIL_CONST_PTR:
                    # OpRegisterIndirectDisplacement
                    dstlabel = il.get_label_for_address(il.arch, tmpil[dest_il].constant)
                elif (tmpil[dest_il].operation == LowLevelILOperation.LLIL_SX and
                      tmpil[dest_il].operands[0].operation == LowLevelILOperation.LLIL_CONST):
                    # OpAbsolute
                    dstlabel = il.get_label_for_address(il.arch, tmpil[dest_il].operands[0].constant)
            except:
                raise

            if dstlabel is not None:
                il.append(
                    il.goto(dstlabel)
                )
            else:
                il.append(
                    il.jump(dest.get_address_il(il))
                )
        elif instr in ('jsr', 'bsr'):
            # TODO: need to save 'sr' to stack?
            il.append(
                il.call(dest.get_address_il(il))
            )
            if RTS_PASS_FLAGS:
                il.append(il.set_flag('c', il.reg(1, 'rc')))
        elif instr == 'callm':
            # TODO
            il.append(il.unimplemented())
        elif instr == 'cpush':
            # TODO
            il.append(il.unimplemented())
        elif instr in ('bhi', 'bls', 'bcc', 'bcs', 'bne', 'beq', 'bvc', 'bvs',
                    'bpl', 'bmi', 'bge', 'blt', 'bgt', 'ble'):
            flag_cond = ConditionMapping[instr[1:]]

            tmpil = LowLevelILFunction(il.arch)
            _dest_il = dest.get_address_il2(tmpil)
            dest_il = _dest_il[0]
            for i in _dest_il[1]:
                tmpil.append(i)

            t = None
            if tmpil[dest_il].operation == LowLevelILOperation.LLIL_CONST_PTR:
                t = il.get_label_for_address(il.arch, tmpil[dest_il].constant)

            indirect = False

            if t is None:
                t = LowLevelILLabel()
                indirect = True

            f_label_found = True

            f = il.get_label_for_address(il.arch, il.current_address+length)

            if f is None:
                f = LowLevelILLabel()
                f_label_found = False

            cond_il = il.flag_condition(flag_cond)
            il.append(
                il.if_expr(cond_il, t, f)
            )

            if indirect:
                il.mark_label(t)
                il.append(il.jump(dest.get_address_il(il)))

            if not f_label_found:
                il.mark_label(f)
        elif instr in ('dbt', 'dbf', 'dbhi', 'dbls', 'dbcc', 'dbcs', 'dbne',
                    'dbeq', 'dbvc', 'dbvs', 'dbpl', 'dbmi', 'dbge', 'dblt',
                    'dbgt', 'dble'):
            flag_cond = ConditionMapping.get(instr[2:], None)
            tmpil = LowLevelILFunction(il.arch)
            _dest_il = dest.get_address_il2(tmpil)
            dest_il = _dest_il[0]
            for i in _dest_il[1]:
                tmpil.append(i)
            cond_il = None

            if flag_cond is not None:
                cond_il = il.flag_condition(flag_cond)
            elif instr == 'dbt':
                cond_il = il.const(1, 1)
            elif instr == 'dbf':
                cond_il = il.const(1, 0)

            if cond_il is None:
                il.append(il.unimplemented())
            else:
                branch = None
                if tmpil[dest_il].operation == LowLevelILOperation.LLIL_CONST_PTR:
                    branch = il.get_label_for_address(il.arch, tmpil[dest_il].constant)

                indirect = False

                if branch is None:
                    branch = LowLevelILLabel()
                    indirect = True

                skip_label_found = True

                skip = il.get_label_for_address(il.arch, il.current_address+length)

                if skip is None:
                    skip = LowLevelILLabel()
                    skip_label_found = False

                decrement = LowLevelILLabel()

                il.append(
                    il.if_expr(cond_il, skip, decrement)
                )

                il.mark_label(decrement)

                il.append(
                    il.set_reg(2,
                        LLIL_TEMP(0),
                        il.sub(2,
                            source.get_source_il(il),
                            il.const(2, 1)
                        )
                    )
                )

                il.append(
                    source.get_dest_il(il, il.reg(2, LLIL_TEMP(0)))
                )

                il.append(
                    il.if_expr(
                        il.compare_equal(2,
                            il.reg(2, LLIL_TEMP(0)),
                            il.const(2, -1)
                        ),
                        skip,
                        branch
                    )
                )

                if indirect:
                    il.mark_label(branch)
                    il.append(il.jump(dest.get_address_il(il)))

                if not skip_label_found:
                    il.mark_label(skip)
        elif instr in ('st', 'sf', 'shi', 'sls', 'scc', 'scs', 'sne', 'seq',
                    'svc', 'svs', 'spl', 'smi', 'sge', 'slt', 'sgt', 'sle'):
            flag_cond = ConditionMapping.get(instr[1:], None)
            cond_il = None

            if flag_cond is not None:
                cond_il = il.flag_condition(flag_cond)
            elif instr == 'st':
                cond_il = il.const(1, 1)
            elif instr == 'sf':
                cond_il = il.const(1, 0)

            if cond_il is None:
                il.append(il.unimplemented())
            else:
                skip_label_found = True

                skip = il.get_label_for_address(il.arch, il.current_address+length)

                if skip is None:
                    skip = LowLevelILLabel()
                    skip_label_found = False

                set_dest = LowLevelILLabel()
                clear_dest = LowLevelILLabel()

                il.append(
                    il.if_expr(cond_il, set_dest, clear_dest)
                )

                il.mark_label(set_dest)

                il.append(
                    dest.get_dest_il(il, il.const(1, 1))
                )

                il.append(
                    il.goto(skip)
                )

                il.mark_label(clear_dest)

                il.append(
                    dest.get_dest_il(il, il.const(1, 0))
                )

                il.append(
                    il.goto(skip)
                )

                if not skip_label_found:
                    il.mark_label(skip)
        elif instr == 'rtd':
            il.append(
                il.set_reg(4,
                    LLIL_TEMP(0),
                    il.pop(4)
                )
            )
            il.append(
                il.set_reg(4, 'sp',
                    il.add(4,
                        il.reg(4, 'sp'),
                        il.sign_extend(4, il.const(2,
                            dest.value),
                            0
                        )
                    )
                )
            )
            il.append(
                il.ret(
                    il.reg(4, LLIL_TEMP(0))
                )
            )
        elif instr == 'rte':
            il.append(
                il.set_reg(2,
                    "sr",
                    il.pop(2)
                )
            )
            il.append(
                il.ret(
                    il.pop(4)
                )
            )
        elif instr == 'rtm':
            # TODO
            il.append(il.unimplemented())
        elif instr == 'rtr':
            il.append(
                il.set_reg(2,
                    'ccr',
                    il.pop(2)
                )
            )
            il.append(
                il.ret(
                    il.pop(4)
                )
            )
        elif instr == 'rts':
            if RTS_PASS_FLAGS:
                il.append(il.set_reg(1, 'rc', il.flag('c')))

            il.append(
                il.ret(
                    il.pop(4)
                )
            )
        elif instr in ('trapv', 'trapt', 'trapf', 'traphi', 'trapls', 'trapcc',
                    'trapcs', 'trapne', 'trapeq', 'trapvc', 'trapvs', 'trappl',
                    'trapmi', 'trapge', 'traplt', 'trapgt', 'traple'):
            flag_cond = ConditionMapping.get(instr[4:], None)
            cond_il = None

            if flag_cond is not None:
                cond_il = il.flag_condition(flag_cond)
            elif instr == 'trapt':
                cond_il = il.const(1, 1)
            elif instr == 'trapf':
                cond_il = il.const(1, 0)
            elif instr == 'trapv':
                cond_il = il.flag_condition(LowLevelILFlagCondition.LLFC_O)

            if cond_il is None:
                il.append(il.unimplemented())
            else:
                skip_label_found = True

                skip = il.get_label_for_address(il.arch, il.current_address+length)

                if skip is None:
                    skip = LowLevelILLabel()
                    skip_label_found = False

                trap = LowLevelILLabel()

                il.append(
                    il.if_expr(cond_il, trap, skip)
                )

                il.mark_label(trap)

                il.append(
                    il.system_call()
                )

                il.append(
                    il.goto(skip)
                )

                if not skip_label_found:
                    il.mark_label(skip)
        elif instr in ('trap', 'illegal', 'bkpt'):
            il.append(il.system_call())
        elif instr in ('bgnd', 'nop', 'reset', 'stop'):
            il.append(il.nop())
        else:
            il.append(il.unimplemented())

    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        instr, length, _size, _source, dest, _third = self.disasm.decode_instruction(data, addr)
        if instr == 'unimplemented':
            return None

        result = InstructionInfo()
        result.length = length

        if instr in ('rtd', 'rte', 'rtr', 'rts'):
            result.add_branch(BranchType.FunctionReturn)
        elif instr in ('jmp', 'jsr',
                    'bra', 'bsr', 'bhi', 'bls', 'bcc', 'bcs', 'bne', 'beq',
                    'bvc', 'bvs', 'bpl', 'bmi', 'bge', 'blt', 'bgt', 'ble',
                    'dbt', 'dbf', 'dbhi', 'dbls', 'dbcc', 'dbcs', 'dbne',
                    'dbeq', 'dbvc', 'dbvs', 'dbpl', 'dbmi', 'dbge', 'dblt',
                    'dbgt', 'dble'):
            conditional = False
            branch_dest = None

            bt = BranchType.UnresolvedBranch
            if instr in ('jmp', 'bra'):
                bt = BranchType.UnconditionalBranch
            elif instr in ('jsr', 'bsr'):
                bt = BranchType.CallDestination
            else:
                conditional = True

            if isinstance(dest, OpAbsolute):
                branch_dest = dest.address
            elif isinstance(dest, OpRegisterIndirect):
                if dest.reg == 'pc':
                    branch_dest = addr+2
                else:
                    bt = BranchType.UnresolvedBranch
            elif isinstance(dest, OpRegisterIndirectDisplacement):
                if dest.reg == 'pc':
                    branch_dest = addr+2+dest.offset
                else:
                    bt = BranchType.UnresolvedBranch
            elif isinstance(dest, OpRegisterIndirectIndex):
                bt = BranchType.UnresolvedBranch

            if conditional:
                # pylint: disable=unsubscriptable-object
                if instr[0:2] == 'db':
                    result.add_branch(BranchType.TrueBranch, addr+length)
                    result.add_branch(BranchType.FalseBranch, branch_dest)
                else:
                    result.add_branch(BranchType.TrueBranch, branch_dest)
                    result.add_branch(BranchType.FalseBranch, addr+length)
            else:
                if bt == BranchType.IndirectBranch or bt == BranchType.UnresolvedBranch or branch_dest is None:
                    result.add_branch(bt)
                else:
                    result.add_branch(bt, branch_dest)

        return result

    def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List['function.InstructionTextToken'], int]]:
        instr, length, size, source, dest, third = self.disasm.decode_instruction(data, addr)

        if size is not None:
            # pylint: disable=invalid-sequence-index
            instr += SizeSuffix[size]

        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, "%-10s" % instr)]

        if source is not None:
            tokens += source.format(addr)

        if dest is not None:
            if source is not None:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]
            tokens += dest.format(addr)

        if third is not None:
            if source is not None or dest is not None:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]
            tokens += third.format(addr)

        return tokens, length

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        instr, length, size, source, dest, third = self.disasm.decode_instruction(data, addr)

        if instr == 'movem':
            # movem overrides default predecrement/postincrement IL generation

            self.generate_instruction_il(il, instr, length, size, source, dest, third)

        elif instr is not None:

            # predecrement
            if source is not None:
                pre_il = source.get_pre_il(il)
                if pre_il is not None:
                    il.append(pre_il)

            if dest is not None:
                pre_il = dest.get_pre_il(il)
                if pre_il is not None:
                    il.append(pre_il)

            if third is not None:
                pre_il = third.get_pre_il(il)
                if pre_il is not None:
                    il.append(pre_il)

            self.generate_instruction_il(il, instr, length, size, source, dest, third)

            # postincrement
            if source is not None:
                post_il = source.get_post_il(il)
                if post_il is not None:
                    il.append(post_il)

            if dest is not None:
                post_il = dest.get_post_il(il)
                if post_il is not None:
                    il.append(post_il)

            if third is not None:
                post_il = third.get_post_il(il)
                if post_il is not None:
                    il.append(post_il)
        else:
            il.append(il.unimplemented())
        return length

    def get_flag_write_low_level_il(self, op: LowLevelILOperation, size: int, write_type, flag, operands, il: LowLevelILFunction) -> ExpressionIndex:
        # special
        if flag == 'x':
            if (op == LowLevelILOperation.LLIL_SUB) or (op == LowLevelILOperation.LLIL_ADD):
                # subq, add: x is carry
                return self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il)
            # if (op == LowLevelILOperation.LLIL_ASR) or (op == LowLevelILOperation.LLIL_LSR):
            #     # asr, lsr: if shift is 0, x is unaffected, otherwise x is carry
            #     # FIXME: shift size isn't always a constant
            #     if operands[1] != 0:
            #         FIXME: carry needs to be lifted as well
            #         return self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il)
            #     return il.flag('x')

        # carry
        if flag == 'c':
            if (op == LowLevelILOperation.LLIL_STORE) or (op == LowLevelILOperation.LLIL_SET_REG):
                # move, moveq: c is cleared
                return il.const(1, 0)
            if (op == LowLevelILOperation.LLIL_AND) or (op == LowLevelILOperation.LLIL_OR) or (op == LowLevelILOperation.LLIL_XOR):
                # andi, ori, eori: c is cleared
                return il.const(1, 0)

        # overflow
        if flag == 'v':
            if (op == LowLevelILOperation.LLIL_STORE) or (op == LowLevelILOperation.LLIL_SET_REG):
                # move, moveq: v is cleared
                return il.const(1, 0)
            if (op == LowLevelILOperation.LLIL_AND) or (op == LowLevelILOperation.LLIL_OR) or (op == LowLevelILOperation.LLIL_XOR):
                # andi, ori, eori: v is cleared
                return il.const(1, 0)


        if not self._flags:
            self._flags = {}
        request = {'op': str(LowLevelILOperation(op)), 'write_type': write_type, 'flag': flag}
        srequest = str(request)
        if not srequest in self._flags:
            self._flags[srequest] = 0
        self._flags[srequest] += 1

        # if flag == 'c':
        #     if (op == LowLevelILOperation.LLIL_SUB) or (op == LowLevelILOperation.LLIL_SBB):
        #         # Subtraction carry flag is inverted from the commom implementation
        #         return il.not_expr(0, self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il))
        #     # Other operations use a normal carry flag
        #     return self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il)
        # return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

    def is_never_branch_patch_available(self, data, addr: int = 0) -> bool:
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60:
            # BRA, BSR, Bcc
            return True
        if data[0] == 0x4e and data[1] & 0x80 == 0x80:
            # JMP, JSR
            return True
        return False

    def is_invert_branch_patch_available(self, data: bytes, addr: int = 0) -> bool:
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60 and data[0] & 0xfe != 0x60:
            # Bcc
            return True
        return False

    def is_always_branch_patch_available(self, data: bytes, addr: int = 0) -> bool:
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60 and data[0] & 0xfe != 0x60:
            # Bcc
            return True
        return False

    def is_skip_and_return_zero_patch_available(self, data: bytes, addr: int = 0) -> bool:
        return self.skip_and_return_value(data, addr, 0)

    def is_skip_and_return_value_patch_available(self, data: bytes, addr: int = 0) -> bool:
        data = bytearray(data)
        if data[0] == 0x61:
            # BSR
            return True
        if data[0] == 0x4e and data[1] & 0xc0 == 0x80:
            # JSR
            return True
        return False

    def convert_to_nop(self, data: bytes, addr: int = 0) -> Optional[bytes]:
        count = int(len(data)/2)
        if count*2 != len(data):
            return None
        return b'\x4e\x71' * count

    def never_branch(self, data, addr):
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60:
            # BRA, BSR, Bcc
            return self.convert_to_nop(data, addr)
        if data[0] == 0x4e and data[1] & 0x80 == 0x80:
            # JMP, JSR
            return self.convert_to_nop(data, addr)
        return None

    def invert_branch(self, data: bytes, addr: int = 0) -> Optional[bytes]:
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60 and data[0] & 0xfe != 0x60:
            # Bcc
            return bytearray([data[0]^1])+data[1:]
        return None

    def always_branch(self, data: bytes, addr: int = 0) -> Optional[bytes]:
        data = bytearray(data)
        if data[0] & 0xf0 == 0x60 and data[0] & 0xfe != 0x60:
            # Bcc
            return b'\x60'+data[1:]
        return None

    def skip_and_return_value(self, data: bytes, addr: int, value: int) -> Optional[bytes]:
        count = int(len(data)/2)
        if count*2 != len(data):
            return None
        data = bytearray(data)
        ok = False
        if data[0] == 0x61:
            # BSR
            ok = True
        if data[0] == 0x4e and data[1] & 0xc0 == 0x80:
            # JSR
            ok = True
        if not ok:
            return None

        if value > 0x80000000:
            value = value - 0x100000000

        if value >= -128 and value <= 127 and len(data) >= 2:
            value = value & 0xff
            return b'\x70'+struct.pack('>b',value)+b'\x4e\x71'*(count-1)

        if len(data) >= 6:
            return b'\x20\x3C'+struct.pack('>l', value)+b'\x4e\x71'*(count-3)

        return None


class M68008(M68000):
    name = "M68008"


class M68010(M68000):
    name = "M68010"
    control_registers = {
        0x000: 'sfc',
        0x001: 'dfc',
        0x800: 'usp',
        0x801: 'vbr',
    }

    # add BKPT, MOVE from CCR, MOVEC, MOVES, RTD


class M68020(M68010):
    name = "M68020"
    control_registers = {
        0x000: 'sfc',
        0x001: 'dfc',
        0x800: 'usp',
        0x801: 'vbr',
        0x002: 'cacr',
        0x802: 'caar',
        0x803: 'msp',
        0x804: 'isp',
    }
    address_size = 4
    memory_indirect = True
    movem_store_decremented = True

    # add BFCHG, BFCLR, BFEXTS, BFEXTU, BFFO, BFINS, BFSET, BFTST, CALLM, CAS, CAS2, CHK2, CMP2, cpBcc, cpDBcc, cpGEN, cpRESTORE, cpSAVE, cpScc, cpTRAPcc
    # DIVSL, DIVUL, EXTB, PACK, RTM, TRAPcc, UNPK
    # add memory indirect addressing


class M68030(M68020):
    name = "M68030"

    # remove CALLM, RTM
    # add PFLUSH, PFLUSHA, PLOAD, PMOVE, PTEST


class M68040(M68030):
    name = "M68040"
    control_registers = {
        0x000: 'sfc',
        0x001: 'dfc',
        0x800: 'usp',
        0x801: 'vbr',
        0x002: 'cacr',
        0x803: 'msp',
        0x804: 'isp',
        0x003: 'tc',
        0x004: 'itt0',
        0x005: 'itt1',
        0x006: 'dtt0',
        0x007: 'dtt1',
        0x805: 'mmusr',
        0x806: 'urp',
        0x807: 'srp',
    }

    # remove cpBcc, cpDBcc, cpGEN, cpRESTORE, cpSAVE, cpScc, cpTRAPcc, PFLUSHA, PLOAD, PMOVE
    # add CINV, CPUSH, floating point, MOVE16


class M68LC040(M68040):
    name = "M68LC040"


class M68EC040(M68040):
    name = "M68EC040"
    control_registers = {
        0x000: 'sfc',
        0x001: 'dfc',
        0x800: 'usp',
        0x801: 'vbr',
        0x002: 'cacr',
        0x803: 'msp',
        0x804: 'isp',
        0x004: 'iacr0',
        0x005: 'iacr1',
        0x006: 'dacr0',
        0x007: 'dacr1'
    }


class M68330(M68010):
    name = "M68330"
    movem_store_decremented = True
    # AKA CPU32

    # add BGND, CHK2, CMP2, DIVSL, DIVUL, EXTB, LPSTOP, TBLS, TBLSN, TBLU, TBLUN, TRAPcc


class M68340(M68330):
    name = "M68340"


def create_vector_table(view, addr, size=256):
    vectors = {
        0: 'reset_initial_interrupt_stack_pointer',
        1: 'reset_initial_program_counter',
        2: 'access_fault',
        3: 'address_error',
        4: 'illegal_instruction',
        5: 'integer_divide_by_zero',
        6: 'chk_chk2_instruction',
        7: 'ftrapcc_trapcc_trapv_instruction',
        8: 'privilege_violation',
        9: 'trace',
        10: 'line_1010_emulator',
        11: 'line_1111_emulator',
        # 12 unassigned_reserved
        13: 'coprocessor_protocol_violation',
        14: 'format_error',
        15: 'uninitialized_interrupt',
        # 16-23 unassigned_reserved
        24: 'spurious_interrupt',
        25: 'level_1_interrupt_autovector',
        26: 'level_2_interrupt_autovector',
        27: 'level_3_interrupt_autovector',
        28: 'level_4_interrupt_autovector',
        29: 'level_5_interrupt_autovector',
        30: 'level_6_interrupt_autovector',
        31: 'level_7_interrupt_autovector',
        32: 'trap_0_instruction',
        33: 'trap_1_instruction',
        34: 'trap_2_instruction',
        35: 'trap_3_instruction',
        36: 'trap_4_instruction',
        37: 'trap_5_instruction',
        38: 'trap_6_instruction',
        39: 'trap_7_instruction',
        40: 'trap_8_instruction',
        41: 'trap_9_instruction',
        42: 'trap_10_instruction',
        43: 'trap_11_instruction',
        44: 'trap_12_instruction',
        45: 'trap_13_instruction',
        46: 'trap_14_instruction',
        47: 'trap_15_instruction',
        48: 'fp_branch_or_set_on_unordered_condition',
        49: 'fp_inexact_result',
        50: 'fp_divide_by_zero',
        51: 'fp_underflow',
        52: 'fp_operand_error',
        53: 'fp_overflow',
        54: 'fp_signaling_nan',
        55: 'fp_unimplemented_data_type',
        56: 'mmu_configuration_error',
        57: 'mmu_illegal_operation_error',
        58: 'mmu_access_level_violation_error',
        # 59-63 unassigned_reserved
    }
    for k in range(0, 192):
        vectors[k+64] = 'user_%d' % k

    t = view.parse_type_string("void *")[0]

    for k in range(size):
        name = vectors.get(k, 'unassigned_reserved')

        view.define_user_symbol(Symbol(SymbolType.DataSymbol, addr+4*k, "_vector_%d_%s" % (k, name)))
        view.define_user_data_var(addr+4*k, t)
        value = struct.unpack(">L", view.read(addr+4*k, 4))[0]

        if k > 0:
            view.define_user_symbol(Symbol(SymbolType.FunctionSymbol, value, "vector_%d_%s" % (k, name)))
            if value > 0:
                view.add_entry_point(value)


def prompt_create_vector_table(view, addr=None):
    architectures = ['M68000', 'M68008', 'M68010', 'M68020', 'M68030', 'M68040', 'M68LC040', 'M68EC040', 'M68330', 'M68340']
    size_choices = ['Full (256)', 'MMU (59)', 'FP (56)', 'Traps (48)', 'Interrupts (32)']
    size_raw = [256, 59, 56, 48, 32]

    if addr is None:
        addr = 0

    need_arch = True
    if view.platform is not None and view.platform.arch.name in architectures:
        # 68k arch already selected
        need_arch = False

    address_field = AddressField('Address', view, addr)
    arch_field = ChoiceField('Architecture', architectures)
    size_field = ChoiceField('Table size', size_choices)

    res = False

    if need_arch:
        res = get_form_input([address_field, arch_field, size_field], 'Create M68k vector table')
    else:
        res = get_form_input([address_field, size_field], 'Create M68k vector table')

    if res:
        address = address_field.result
        size = size_raw[size_field.result]

        if need_arch:
            arch = architectures[arch_field.result]
            view.platform = Architecture[arch].standalone_platform

        create_vector_table(view, address, size)

