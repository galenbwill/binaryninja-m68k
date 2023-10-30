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

from typing import List, Optional, Tuple

import struct
import traceback
import os

from binaryninja.architecture import Architecture, RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel, LLIL_TEMP, LowLevelILFunction, ExpressionIndex
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import AddressField, ChoiceField, get_form_input
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (Endianness, BranchType, InstructionTextTokenType,
        LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag,
        ImplicitRegisterExtend, SymbolType)
from binaryninja import BinaryViewType


# Shift syles
SHIFT_SYLE_ARITHMETIC = 0,
SHIFT_SYLE_LOGICAL = 1,
SHIFT_SYLE_ROTATE_WITH_EXTEND = 2,
SHIFT_SYLE_ROTATE = 3,

ShiftStyle = [
    'as',  # SHIFT_SYLE_ARITHMETIC
    'ls',  # SHIFT_SYLE_LOGICAL
    'rox', # SHIFT_SYLE_ROTATE_WITH_EXTEND
    'ro'   # SHIFT_SYLE_ROTATE
]

BITFIELD_STYLE_TST = 0,
BITFIELD_STYLE_EXTU = 1,
BITFIELD_STYLE_CHG = 2,
BITFIELD_STYLE_EXTS = 3,
BITFIELD_STYLE_CLR = 4,
BITFIELD_STYLE_FFO = 5,
BITFIELD_STYLE_SET = 6,
BITFIELD_STYLE_INS = 7,

BitfieldStyle = [
    "tst", # BITFIELD_STYLE_TST
    "extu", # BITFIELD_STYLE_EXTU
    "chg", # BITFIELD_STYLE_CHG
    "exts", # BITFIELD_STYLE_EXTS
    "clr", # BITFIELD_STYLE_CLR
    "ffo", # BITFIELD_STYLE_FFO
    "set", # BITFIELD_STYLE_SET
    "ins", # BITFIELD_STYLE_INS
]


# Condition codes
CONDITION_TRUE = 0
CONDITION_FALSE = 1
CONDITION_HIGH = 2
CONDITION_LESS_OR_SAME = 3
CONDITION_CARRY_CLEAR = 4
CONDITION_CARRY_SET = 5
CONDITION_NOT_EQUAL = 6
CONDITION_EQUAL = 7
CONDITION_OVERFLOW_CLEAR = 8
CONDITION_OVERFLOW_SET = 9
CONDITION_PLUS = 10
CONDITION_MINUS = 11
CONDITION_GREATER_OR_EQUAL = 12
CONDITION_LESS_THAN = 13
CONDITION_GREATER_THAN = 14
CONDITION_LESS_OR_EQUAL = 15

Condition = [
    't',  # CONDITION_TRUE
    'f',  # CONDITION_FALSE
    'hi', # CONDITION_HIGH
    'ls', # CONDITION_LESS_OR_SAME
    'cc', # CONDITION_CARRY_CLEAR
    'cs', # CONDITION_CARRY_SET
    'ne', # CONDITION_NOT_EQUAL
    'eq', # CONDITION_EQUAL
    'vc', # CONDITION_OVERFLOW_CLEAR
    'vs', # CONDITION_OVERFLOW_SET
    'pl', # CONDITION_PLUS
    'mi', # CONDITION_MINUS
    'ge', # CONDITION_GREATER_OR_EQUAL
    'lt', # CONDITION_LESS_THAN
    'gt', # CONDITION_GREATER_THAN
    'le'  # CONDITION_LESS_OR_EQUAL
]

# Registers
REGISTER_D0 = 0
REGISTER_D1 = 1
REGISTER_D2 = 2
REGISTER_D3 = 3
REGISTER_D4 = 4
REGISTER_D5 = 5
REGISTER_D6 = 6
REGISTER_D7 = 7
REGISTER_A0 = 8
REGISTER_A1 = 9
REGISTER_A2 = 10
REGISTER_A3 = 11
REGISTER_A4 = 12
REGISTER_A5 = 13
REGISTER_A6 = 14
REGISTER_A7 = 15

Registers = [
    'd0', # REGISTER_D0
    'd1', # REGISTER_D1
    'd2', # REGISTER_D2
    'd3', # REGISTER_D3
    'd4', # REGISTER_D4
    'd5', # REGISTER_D5
    'd6', # REGISTER_D6
    'd7', # REGISTER_D7
    'a0', # REGISTER_A0
    'a1', # REGISTER_A1
    'a2', # REGISTER_A2
    'a3', # REGISTER_A3
    'a4', # REGISTER_A4
    'a5', # REGISTER_A5
    'a6', # REGISTER_A6
    'sp'  # REGISTER_A7
]

# Sizes
SIZE_BYTE = 0
SIZE_WORD = 1
SIZE_LONG = 2

SizeSuffix = [
    '.b', # SIZE_BYTE
    '.w', # SIZE_WORD
    '', # SIZE_LONG
]


def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))


# Operands

class Operand:
    def format(self, addr: int) -> List[InstructionTextToken]:
        raise NotImplementedError

    def get_pre_il(self, il: LowLevelILFunction) -> Optional[ExpressionIndex]:
        raise NotImplementedError

    def get_post_il(self, il: LowLevelILFunction) -> Optional[ExpressionIndex]:
        raise NotImplementedError

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[Optional[ExpressionIndex], List[ExpressionIndex]]:
        raise NotImplementedError

    def get_address_il(self, il: LowLevelILFunction) -> Optional[ExpressionIndex]:
        return self.get_address_il2(il)[0]

    def get_source_il(self, il: LowLevelILFunction) -> Optional[ExpressionIndex]:
        raise NotImplementedError

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> Optional[ExpressionIndex]:
        raise NotImplementedError

class OpRegisterDirect(Operand):
    def __init__(self, size: int, reg: str):
        self.size = size
        self.reg = reg

    def __repr__(self):
        return "OpRegisterDirect(%d, %s)" % (self.size, self.reg)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # a0, d0
        return [
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg)
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.unimplemented()
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        if self.reg == 'ccr':
            c = il.flag_bit(1, 'c', 0)
            v = il.flag_bit(1, 'v', 1)
            z = il.flag_bit(1, 'z', 2)
            n = il.flag_bit(1, 'n', 3)
            x = il.flag_bit(1, 'x', 4)
            print(self)
            # FIXME: return array
            return il.or_expr(1, il.or_expr(1, il.or_expr(1, il.or_expr(1, c, v), z), n), x)
        else:
            return il.reg(1 << self.size, self.reg)

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg in ['ccr', 'sr']:
            return il.unimplemented()

        if self.size == SIZE_BYTE:
            if self.reg[0] == 'a' or self.reg == 'sp':
                return il.unimplemented()
        if self.size == SIZE_LONG:
            if value is None:
                return il.unimplemented()
        return il.set_reg(1 << self.size, self.reg + SizeSuffix[self.size], value, flags)


class OpRegisterDirectPair(Operand):
    def __init__(self, size: int, reg1: str, reg2: str):
        self.size = size
        self.reg1 = reg1
        self.reg2 = reg2

    def __repr__(self):
        return "OpRegisterDirectPair(%d, %s, %s)" % (self.size, self.reg1, self.reg2)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # d0:d1
        return [
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg1),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ":"),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg2)
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.unimplemented()
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return (il.reg(1 << self.size, self.reg1), il.reg(1 << self.size, self.reg2))

    def get_dest_il(self, il: LowLevelILFunction, values, flags=0) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return (il.set_reg(1 << self.size, self.reg1, values[0], flags), il.set_reg(1 << self.size, self.reg2, values[1], flags))


class OpRegisterMovemList(Operand):
    def __init__(self, size: int, regs: List[str]):
        self.size = size
        self.regs = regs

    def __repr__(self):
        return "OpRegisterMovemList(%d, %s)" % (self.size, repr(self.regs))

    def format(self, addr: int) -> List[InstructionTextToken]:
        # d0-d7/a0/a2/a4-a7
        if len(self.regs) == 0:
            return []
        tokens = [InstructionTextToken(InstructionTextTokenType.RegisterToken, self.regs[0])]
        last = self.regs[0]
        first = None
        for reg in self.regs[1:]:
            if Registers[Registers.index(last)+1] == reg and reg != 'a0':
                if first is None:
                    first = last
                last = reg
            else:
                if first is not None:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "-"))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, last))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "/"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, reg))
                first = None
                last = reg
        if first is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "-"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, last))
        return tokens

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.unimplemented()
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return [il.reg(1 << self.size, reg) for reg in self.regs]

    def get_dest_il(self, il: LowLevelILFunction, values, flags=0) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return [il.set_reg(1 << self.size, reg, val, flags) for reg, val in zip(self.regs, values)]


class OpRegisterIndirect(Operand):
    def __init__(self, size: int, reg: str):
        self.size = size
        self.reg = reg

    def __repr__(self):
        return "OpRegisterIndirect(%d, %s)" % (self.size, self.reg)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # (a0)
        return [
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")")
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.reg(4, self.reg)
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        #return il.store(1 << self.size, self.get_address_il(il), value, flags)
        return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpRegisterIndirectPair(Operand):
    def __init__(self, size: int, reg1: str, reg2: str):
        self.size = size
        self.reg1 = reg1
        self.reg2 = reg2

    def __repr__(self):
        return "OpRegisterIndirectPair(%d, %s, %s)" % (self.size, self.reg1, self.reg2)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # d0:d1
        return [
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg1),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ":"),
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg2),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")")
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # return (il.reg(4, self.reg1), il.reg(4, self.reg2))
        a = il.reg(4, self.reg1)
        b = il.reg(4, self.reg2)
        return ((a, b), [a, b])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return (il.load(1 << self.size, il.reg(4, self.reg1)), il.load(1 << self.size, il.reg(4, self.reg2)))

    def get_dest_il(self, il: LowLevelILFunction, values, flags=0) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        #return (il.store(1 << self.size, il.reg(4, self.reg1), values[0], flags), il.store(1 << self.size, il.reg(4, self.reg2), values[1], flags))
        return (il.store(1 << self.size, il.reg(4, self.reg1), values[0]), il.store(1 << self.size, il.reg(4, self.reg2), values[1]))


class OpRegisterIndirectPostincrement(Operand):
    def __init__(self, size: int, reg: str):
        self.size = size
        self.reg = reg

    def __repr__(self):
        return "OpRegisterIndirectPostincrement(%d, %s)" % (self.size, self.reg)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # (a0)+
        return [
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"),
            InstructionTextToken(InstructionTextTokenType.TextToken, "+")
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return il.set_reg(4,
            self.reg,
            il.add(4,
                il.reg(4, self.reg),
                il.const(4, 1 << self.size)
            )
        )

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.reg(4, self.reg)
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        #return il.store(1 << self.size, self.get_address_il(il), value, flags)
        return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpRegisterIndirectPredecrement(Operand):
    def __init__(self, size: int, reg: str):
        self.size = size
        self.reg = reg

    def __repr__(self):
        return "OpRegisterIndirectPredecrement(%d, %s)" % (self.size, self.reg)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # -(a0)
        return [
            InstructionTextToken(InstructionTextTokenType.TextToken, "-"),
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")")
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        # FIXME: are we correctly putting them into lists?
        return il.set_reg(4,
            self.reg,
            il.sub(4,
                il.reg(4, self.reg),
                il.const(4, 1 << self.size)
            )
        )

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.reg(4, self.reg)
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        #return il.store(1 << self.size, self.get_address_il(il), value, flags)
        return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpRegisterIndirectDisplacement(Operand):
    def __init__(self, size: int, reg: str, offset: int):
        self.size = size
        self.reg = reg
        self.offset = offset

    def __repr__(self):
        return "OpRegisterIndirectDisplacement(%d, %s, 0x%x)" % (self.size, self.reg, self.offset)

    def format(self, addr: int) -> List[InstructionTextToken]:
        if self.reg == 'pc':
            return [
                InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
                InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "${:08x}".format(addr+2+self.offset), addr+2+self.offset, 4),
                InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")")
            ]
        else:
            # $1234(a0)
            return [
                InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:04x}".format(self.offset), self.offset, 2),
                InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg),
                InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")")
            ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        if self.reg == 'pc':
            r = il.const_pointer(4, il.current_address+2+self.offset)
            return (r, [r])
        else:
            a = il.reg(4, self.reg)
            b = il.const(2, self.offset) if self.offset >= 0 else il.const(2, -self.offset)
            c = il.add(4, a, b) if self.offset >= 0 else il.sub(4, a, b)
            return (c, [a, b, c])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg == 'pc':
            return il.unimplemented()
        else:
            #return il.store(1 << self.size, self.get_address_il(il), value, flags)
            return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpRegisterIndirectIndex(Operand):
    def __init__(self, size: int, reg: str, offset: int, ireg: str, ireg_long: int, scale: int):
        self.size = size
        self.reg = reg
        self.offset = offset
        self.ireg = ireg
        self.ireg_long = ireg_long
        self.scale = scale

    def __repr__(self):
        return "OpRegisterIndirectIndex(%d, %s, 0x%x, %s, %d, %d)" % (self.size, self.reg, self.offset, self.ireg, self.ireg_long, self.scale)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # $1234(a0,a1.l*4)
        tokens = []
        if self.offset != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.offset), self.offset))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.ireg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "."))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "l" if self.ireg_long else 'w'))
        if self.scale != 1:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "*"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "{}".format(self.scale), self.scale))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"))
        return tokens

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # return il.add(4,
        #     il.add(4,
        #         il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg),
        #         il.const(4, self.offset)
        #     ),
        #     il.mult(4,
        #         il.reg(4 if self.ireg_long else 2, self.ireg),
        #         il.const(1, self.scale)
        #     )
        # )
        a = il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg)
        b = il.const(4, self.offset)
        e = il.add(4, a, b)

        c = il.reg(4 if self.ireg_long else 2, self.ireg)
        d = il.const(1, self.scale)
        f = il.mult(4, c, d)

        g = il.add(4, e, f)
        return (g, [a, b, c, d, e, f, g])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg == 'pc':
            return il.unimplemented()
        else:
            #return il.store(1 << self.size, self.get_address_il(il), value, flags)
            return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpMemoryIndirect(Operand):
    def __init__(self, size: int, reg: str, offset: int, outer_displacement: int):
        self.size = size
        self.reg = reg
        self.offset = offset
        self.outer_displacement = outer_displacement

    def __repr__(self):
        return "OpMemoryIndirect(%d, %s, %d, %d)" % (self.size, self.reg, self.offset, self.outer_displacement)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # ([$1234,a0],$1234)
        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["))
        if self.offset != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.offset), self.offset))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"))
        if self.outer_displacement != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.outer_displacement), self.outer_displacement))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"))
        return tokens

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # return il.add(4,
        #     il.load(4,
        #         il.add(4,
        #             il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg),
        #             il.const(4, self.offset)
        #         ),
        #     ),
        #     il.const(4, self.outer_displacement)
        # )
        a = il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg)
        b = il.const(4, self.offset)
        c = il.add(4, a, b)
        d = il.load(4, c)

        e = il.const(4, self.outer_displacement)

        f = il.add(4, d, e)
        return (f, [a, b, c, d, e, f])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg == 'pc':
            return il.unimplemented()
        else:
            #return il.store(1 << self.size, self.get_address_il(il), value, flags)
            return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpMemoryIndirectPostindex(Operand):
    def __init__(self, size: int, reg: str, offset: int, ireg: str, ireg_long: bool, scale: int, outer_displacement: int):
        self.size = size
        self.reg = reg
        self.offset = offset
        self.ireg = ireg
        self.ireg_long = ireg_long
        self.scale = scale
        self.outer_displacement = outer_displacement

    def __repr__(self):
        return "OpMemoryIndirectPostindex(%d, %s, 0x%x, %s, %d, %d, 0x%x)" % (self.size, self.reg, self.offset, self.ireg, self.ireg_long, self.scale, self.outer_displacement)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # ([$1234,a0],a1.l*4,$1234)
        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["))
        if self.offset != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.offset), self.offset))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.ireg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "."))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "l" if self.ireg_long else 'w'))
        if self.scale != 1:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "*"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "{}".format(self.scale), self.scale))
        if self.outer_displacement != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.outer_displacement), self.outer_displacement))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"))
        return tokens

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # j = il.add(4, d, i)
        #     d = il.load(4, c)
        #         c = il.add(4, a, b)
        #             a = il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg),
        #             b = il.const(4, self.offset)
        #         )
        #     ),
        #     i = il.add(4, g, h)
        #         g = il.mult(4, e, f)
        #             e = il.reg(4 if self.ireg_long else 2, self.ireg),
        #             f = il.const(1, self.scale)
        #         ),
        #         h = il.const(4, self.outer_displacement)
        #     )
        # )
        a = il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg)
        b = il.const(4, self.offset)
        c = il.add(4, a, b)
        d = il.load(4, c)

        e = il.reg(4 if self.ireg_long else 2, self.ireg),
        f = il.const(1, self.scale)
        g = il.mult(4, e[0], f)

        h = il.const(4, self.outer_displacement)
        i = il.add(4, g, h)

        j = il.add(4, d, i)
        return (j, [a, b, c, d, e, f, g, h, i, j])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg == 'pc':
            return il.unimplemented()
        else:
            #return il.store(1 << self.size, self.get_address_il(il), value, flags)
            return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpMemoryIndirectPreindex(Operand):
    def __init__(self, size: int, reg: str, offset: int, ireg: str, ireg_long: bool, scale: int, outer_displacement: int):
        self.size = size
        self.reg = reg
        self.offset = offset
        self.ireg = ireg
        self.ireg_long = ireg_long
        self.scale = scale
        self.outer_displacement = outer_displacement

    def __repr__(self):
        return "OpMemoryIndirectPreindex(%d, %s, 0x%x, %s, %d, %d, 0x%x)" % (self.size, self.reg, self.offset, self.ireg, self.ireg_long, self.scale, self.outer_displacement)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # ([$1234,a0,a1.l*4],$1234)
        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["))
        if self.offset != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.offset), self.offset))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.ireg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "."))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "l" if self.ireg_long else 'w'))
        if self.scale != 1:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, "*"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "{}".format(self.scale), self.scale))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"))
        if self.outer_displacement != 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:x}".format(self.outer_displacement), self.outer_displacement))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"))
        return tokens

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # return il.add(4,
        #     il.load(4,
        #         il.add(4,
        #             il.add(4,
        #                 il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg),
        #                 il.const(4, self.offset)
        #             ),
        #             il.mult(4,
        #                 il.reg(4 if self.ireg_long else 2, self.ireg),
        #                 il.const(1, self.scale)
        #             )
        #         )
        #     ),
        #     il.const(4, self.outer_displacement)
        # )
        a = il.const_pointer(4, il.current_address+2) if self.reg == 'pc' else il.reg(4, self.reg)
        b = il.const(4, self.offset)
        c = il.add(4, a, b)

        d = il.reg(4 if self.ireg_long else 2, self.ireg)
        e = il.const(1, self.scale)
        f = il.mult(4, d, e)

        g = il.add(4, c, f)
        h = il.load(4, g)

        i = il.const(4, self.outer_displacement)
        j = il.add(4, h, i)
        return (j, [a, b, c, d, e, f, g, h, i, j])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        if self.reg == 'pc':
            return il.unimplemented()
        else:
            #return il.store(1 << self.size, self.get_address_il(il), value, flags)
            return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpAbsolute(Operand):
    def __init__(self, size, address, address_size, address_width):
        self.size = size
        self.address = address
        self.address_size = address_size
        self.address_width = address_width

    def __repr__(self):
        return "OpAbsolute(%d, 0x%x, %d, %d)" % (self.size, self.address, self.address_size, self.address_width)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # ($1234).w
        return [
            InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("),
            InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "${:0{}x}".format(self.address, 1 << self.address_size), self.address, 1 << self.address_size),
            InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"+SizeSuffix[self.address_size])
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        # return il.sign_extend(self.address_width,
        #     il.const(1 << self.address_size, self.address)
        # )
        a = il.const_pointer(1 << self.address_size, self.address)
        return (a, [a])
        # FIXME: binja 3.0.3355-dev won't show function arguments if we
        # use il.sign_extend.
        # if (1 << self.address_size) == self.address_width:
        #     return (a, [a])
        # b = il.sign_extend(self.address_width, a)
        # return (b, [a, b])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.load(1 << self.size, self.get_address_il(il))

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        #return il.store(1 << self.size, self.get_address_il(il), value, flags)
        return il.expr(LowLevelILOperation.LLIL_STORE, self.get_address_il(il), value, size=1 << self.size, flags=flags)


class OpImmediate(Operand):
    def __init__(self, size, value):
        self.size = size
        self.value = value

    def __repr__(self):
        return "OpImmediate(%d, 0x%x)" % (self.size, self.value)

    def format(self, addr: int) -> List[InstructionTextToken]:
        # #$1234
        return [
            InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
            #InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "${:0{}x}".format(self.value, 1 << self.size), self.value, 1 << self.size)
            InstructionTextToken(InstructionTextTokenType.IntegerToken, "${:0{}x}".format(self.value, 1 << self.size), self.value, 1 << self.size)
        ]

    def get_pre_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_post_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return None

    def get_address_il2(self, il: LowLevelILFunction) -> Tuple[ExpressionIndex, List[ExpressionIndex]]:
        r = il.unimplemented()
        return (r, [r])

    def get_source_il(self, il: LowLevelILFunction) -> ExpressionIndex:
        return il.const(1 << self.size, self.value)

    def get_dest_il(self, il: LowLevelILFunction, value, flags=0) -> ExpressionIndex:
        return il.unimplemented()
