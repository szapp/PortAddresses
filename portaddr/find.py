"""
Utility functions to find symbols by their address or name
"""
from __future__ import print_function
from collections import namedtuple
from ctypes import c_int32
import idaapi
import pyperclip

from .text import strip


__all__ = [
    'name',
    'decode',
    'each',
]


def name(addr):
    """
    Obtain symbol name and information from memory address

    Parameters
    ----------
    addr : int
        Address in memory to investigate

    Returns
    -------
    result : namedutuple
        Information as namedtuple object "Info" with the keys
        name (human readable symbol name), uid (unique identifier of the
        symbol), addr (hexadecimal start address as str prefixed with
        '0x'), offset (hexadecimal offset between the input address and
        the start address as str, not prefixed)
    """
    fnc = idaapi.get_func(addr)
    if fnc:
        addr_spec = int(fnc.startEA)
        offset = addr - addr_spec
    else:
        addr_spec = int(addr)
        offset = 0

    name_spec = 0
    addr_spec += 1
    offset -= 1
    while not name_spec:
        addr_spec -= 1
        offset += 1
        name_hr = idaapi.get_long_name(addr_spec, 16)  # Searchable name
        name_spec = idaapi.get_ea_name(addr_spec)  # Identifiable name

    Info = namedtuple('Info', ['name', 'uid', 'addr', 'offset'])
    return Info(name=name_hr,
                uid=name_spec,
                addr='0x'+hex(addr_spec)[2:].upper(),
                offset=hex(offset)[2:].upper())


def encode(addr):
    """
    Jump to and encode the symbol name of a memory address. The result
    is copied into the clipboard in the form "uid+offset", where uid
    is the unique identifier of the symbol name and offset is the offset
    from the start in hexadecimal representation

    Parameters
    ----------
    addr : int
        Memory address
    """
    idaapi.jumpto(addr)
    info = name(addr)
    print(info)
    pyperclip.copy(info.uid + '+' + info.offset)


def decode(info=None, clipboard=True):  # noqa: C901
    """
    Decode mangled name with offset and find address

    Parameters
    ----------
    info : str
        Mangled name and offset as 'MangledName+HexOffset'. If
        'clipboard', get the string from the clipboard. If None, prompt
        the user for input. Default is None

    clipboard : boolean or str or it
        If True or 'hex', copy the found address as hexadecimal to the
        clipboard. If False, the clipboard is not altered. If 'dec',
        copy the address as 32-bit decimal to the clipboard. If
        'dechex', copy the address as 'DecAddress; //HexAddress'. If
        'const', copy the address as
        'DemangledName = DecAddress; //HexAddress'. If int, same as
        'const' but spaces to fill length of int until the '=', e.g. 20
        results in 'DemangledName       = DecAddress; //HexAddress'.
        Default is True
    """
    if info is None:
        info = idaapi.askstr(42, 'MangledName+HexOffset', 'Address to decode')
    elif info == 'clipboard':
        info = str(pyperclip.paste())
    if info is None:
        return

    chunks = info.split('+')
    if len(chunks) == 1:
        text, offset = info, 0
    else:
        ending = chunks[-1]
        text = info[:-len(ending)-1]
        offset = int(ending, 16)
    addr = int(idaapi.get_name_ea(0, text))
    name_hr = idaapi.get_long_name(addr, 16)
    addr += offset
    idaapi.jumpto(addr)
    addr_str = '0x' + hex(addr)[2:].upper()
    dec = str(c_int32(addr).value)
    dechex = dec + '; //' + addr_str
    dname = strip(name_hr)
    output = dname + ' = ' + dechex
    print(output)
    if clipboard is False:
        return

    if clipboard is True or clipboard == 'hex':
        copy = addr_str
    elif clipboard == 'dec':
        copy = dec
    elif clipboard == 'dechex':
        copy = dechex
    elif clipboard == 'const':
        copy = output
    elif isinstance(clipboard, int) and clipboard > 0:
        copy = ('const int ' + dname + ' ').ljust(clipboard) + '= ' + dechex
    else:
        raise ValueError('Invalid argument for \'clipboard\'.')
    pyperclip.copy(copy)


def each(it):
    """
    Encode and print each memory address in a list

    Parameters
    ----------
    it : iterable or iterator of int
        Sequence of integer memory addresses

    See also
    --------
    encode : Encode and copy the symbol information at an address
    """
    return (encode(i) for i in it)
