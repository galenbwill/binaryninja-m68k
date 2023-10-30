# inspired by https://github.com/Vector35/arch-arm64/blob/staging/arm64test.py
from .m68k import *

SAVE_FLAGS = ''
RESTORE_FLAGS = ''
FINALIZER = 'LLIL_RET(LLIL_POP.d())'

if RTS_PASS_FLAGS:
    SAVE_FLAGS = 'LLIL_SET_REG.b(rc,LLIL_FLAG(c))'
    RESTORE_FLAGS = '; LLIL_SET_FLAG(c,LLIL_REG.b(rc))'
    FINALIZER = SAVE_FLAGS + '; ' + FINALIZER

test_cases = [
    # moveq     #$0000,d0
    (b'\x70\x00', 'LLIL_SET_REG.d{nzvc}(d0,LLIL_CONST.d(0x0))'),

    # subq.b    #$1,d0
    # FIXME: Generate flag 'x'
    (b'\x53\x00', 'LLIL_SET_REG.b(d0.b,LLIL_SUB.b{*}(LLIL_REG.b(d0),LLIL_CONST.b(0x1)))'),

    # jsr 0x5dc1c, no arguments for this call
    (b'\x4e\xb9\x00\x05\xdc\x1c', 'LLIL_CALL(LLIL_CONST_PTR.d(0x5DC1C))' + RESTORE_FLAGS),

    # at 0x53a, jsr 0x546, seems to be correctly interpreted as a call
    (b'\x4e\xba\x00\x0a', 'LLIL_CALL(LLIL_CONST_PTR.d(0xC))' + RESTORE_FLAGS),

    # lea (data_7a9ee[2]),a1
    (b'\x43\xf9\x00\x07\xa9\xf0', 'LLIL_SET_REG.d(a1,LLIL_CONST_PTR.d(0x7A9F0))'),

    # tst.w     d1
    (b'\x4a\x41', 'LLIL_SUB.w{nz}(LLIL_REG.w(d1),LLIL_CONST.w(0x0)); LLIL_SET_FLAG(v,LLIL_CONST.b(0x0)); LLIL_SET_FLAG(c,LLIL_CONST.b(0x0))'),

    # lea       ($279d2e),a0
    # move      $-004(a0),$0074(a6)
    (b'\x41\xf9\x00\x27\x9d\x2e\x2d\x68\xff\xfc\x00\x74', 'LLIL_SET_REG.d(a0,LLIL_CONST_PTR.d(0x279D2E)); LLIL_STORE.d{nzvc}(LLIL_ADD.d(LLIL_REG.d(a6),LLIL_CONST.w(0x74)),LLIL_LOAD.d(LLIL_SUB.d(LLIL_REG.d(a0),LLIL_CONST.w(0x4))))'),

    # beq       (data_10)
    (b'\x67\x00\x00\x0e', 'LLIL_IF(LLIL_FLAG_COND(0,None),1,3); LLIL_JUMP(LLIL_CONST_PTR.d(0x10))'),

    # jmp       ($4c862)
    (b'\x4e\xf9\x00\x04\xc8\x62', 'LLIL_JUMP(LLIL_CONST_PTR.d(0x4C862))'),

    # bra       (data_28)
    (b'\x60\x00\x00\x26', 'LLIL_JUMP(LLIL_CONST_PTR.d(0x28))'),

    # dbf       d7,(data_-2c)
    (b'\x51\xcf\xff\xd4','; '.join(['LLIL_IF(LLIL_CONST.b(0x0),6,1); ' + FINALIZER + '; LLIL_SET_REG.w(temp0,LLIL_SUB.w(LLIL_REG.w(d7),LLIL_CONST.w(0x1))); LLIL_SET_REG.w(d7.w,LLIL_REG.w(temp0)); LLIL_IF(LLIL_CMP_E.w(LLIL_REG.w(temp0),LLIL_CONST.w(0xFFFF)),6,4); LLIL_JUMP(LLIL_CONST_PTR.d(0xFFFFFFD6))'])),

    # bcc       (data_5a)
    (b'\x64\x00\x00\x58', 'LLIL_IF(LLIL_FLAG_COND(7,None),1,3); LLIL_JUMP(LLIL_CONST_PTR.d(0x5A))'),

    # rts
    (b'\x4e\x75', ''),

    # andi.b    #$-2,ccr
    (b'\x02\x3c\x00\xfe', 'LLIL_SET_FLAG(c,LLIL_CONST.b(0x0))'),

    # ori.b     #$1,ccr
    (b'\x00\x3c\x00\x01', 'LLIL_SET_FLAG(c,LLIL_CONST.b(0x1)); LLIL_SET_FLAG(x,LLIL_CONST.b(0x1))'),

    # scs.b     d1
    (b'\x55\xc1', 'LLIL_IF(LLIL_FLAG_COND(3,None),1,3); LLIL_SET_REG.b(d1.b,LLIL_CONST.b(0x1)); LLIL_GOTO(5); LLIL_SET_REG.b(d1.b,LLIL_CONST.b(0x0)); LLIL_GOTO(5)'),

    # swap      d6
    (b'\x48\x46', 'LLIL_SET_REG.d(d6,LLIL_ROR.d(LLIL_REG.d(d6),LLIL_CONST.b(0x10)))'),
]

if RTS_PASS_FLAGS:
    # rtr
    test_cases.append((b'\x4e\x77', 'LLIL_SET_REG.w(ccr,LLIL_POP.w()); LLIL_RET(LLIL_POP.d())'))
else:
    # rtr
    test_cases.append((b'\x4e\x77', 'LLIL_SET_REG.w(ccr,LLIL_POP.w())'))

import re
import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

def il2str(il):
    sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        flags_code = '' if not hasattr(il, 'flags') or not il.flags else '{%s}'%il.flags

        # print size-specified IL constants in hex
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
            tmp = il.operands[0]
            if tmp < 0: tmp = (1<<(il.size*8))+tmp
            tmp = '0x%X' % tmp if il.size else '%d' % il.size
            return '%s%s(%s)' % (il.operation.name, size_code, tmp)
        else:
            return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code, ','.join([il2str(o) for o in il.operands]))
    elif isinstance(il, list):
        return '[' + ','.join([il2str(x) for x in il]) + ']'
    else:
        return str(il)

def instr_to_il(data):
    RETURN = b'\x4e\x75' # rts

    platform = binaryninja.Platform['M68000']
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data + RETURN)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    result = []
    #for block in bv.functions[0].low_level_il:
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)

    ret = FINALIZER
    if result.endswith(ret):
        result = result[0:result.index(ret)]
    if result.endswith('; '):
        result = result[0:-2]

    return result

def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for c in ilstr:
        if c == '(':
            result += '\n'
            depth += 1
            result += '    '*depth
        elif c == ')':
            depth -= 1
        elif c == ',':
            result += '\n'
            result += '    '*depth
            pass
        elif c == ';':
            result += '\n'
            depth = 0
            result += '    '*depth
        elif c == ' ':
            pass
        else:
            result += c
    return result

# print(il_str_to_tree('foo(bar)'))
# print(il_str_to_tree('a(b(c,d(z),e));d(e(f))'))
# print(il_str_to_tree('LLIL_RET(LLIL_POP.d())' + ';LLIL_RET(LLIL_POP.d())'))

def test_all():
    ret = True
    for (test_i, (data, expected)) in enumerate(test_cases):
        actual = instr_to_il(data)
        if actual != expected:
            print('MISMATCH AT TEST %d!' % test_i)
            print('\t   input: %s' % data.hex())
            print('\texpected: %s' % expected)
            # print(il_str_to_tree(expected))
            print('\t  actual: ')
            print(actual)
            print('\t    tree:')
            print(il_str_to_tree(actual))
            print('\n\n')
            ret = False
    return ret
