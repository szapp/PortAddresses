"""
Utility functions to find symbols by their address or name
"""
from __future__ import print_function
from collections import namedtuple
from ctypes import c_int32
import idaapi
from idc import ScreenEA
import pyperclip

from .text import strip


__all__ = [
    'name',
    'encode',
    'decode',
    'batch_encode',
    'batch_decode',
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
        offset = int(addr) - addr_spec
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
        if addr_spec < 0:
            raise IndexError('Could not find any name')

    Info = namedtuple('Info', ['name', 'uid', 'addr', 'offset'])
    return Info(name=name_hr,
                uid=name_spec,
                addr='0x'+hex(addr_spec)[2:].upper(),
                offset=hex(offset)[2:].upper())


def here():
    return name(ScreenEA())


def encode(addr, jump=True, clipboard=True):
    """
    Jump to and encode the symbol name of a memory address. The result
    is copied into the clipboard in the form "uid+offset", where uid
    is the unique identifier of the symbol name and offset is the offset
    from the start in hexadecimal representation

    Parameters
    ----------
    addr : int
        Memory address

    jump : bool, optional
        Jump to the address

    clipboard : bool, optional
        Copy the result to the clipboard. If False, the clipboard is not
        altered. Default is True

    Returns
    -------
    output : str
        Formatted symbol name and offset
    """
    if jump:
        idaapi.jumpto(addr)
    try:
        info = name(addr)
        output = info.uid + '+' + info.offset
    except IndexError:
        output = 'not_found__invalid_address'

    if clipboard is True:
        pyperclip.copy(output)

    return output


def decode(info=None, out_format='hex', jump=True,  # noqa: C901
           clipboard=True):
    """
    Decode mangled name with offset and find address

    Parameters
    ----------
    info : str, optional
        Mangled name and offset as 'MangledName+HexOffset'. If
        'clipboard', get the string from the clipboard. If None, prompt
        the user for input. Default is None

    out_format : {'dec', 'hexdec', 'assign'} or int, optional
        Format of the address output. If 'hex', format as hexadecimal.
        If 'dec', format as 32-bit decimal. If 'dechex', format as
        'DecAddress; //HexAddress'. If 'assign', as
        'DemangledName = DecAddress; //HexAddress'. If int, same as
        'assign' but spaces to fill length of int until the '=', e.g. 20
        results in 'DemangledName       = DecAddress; //HexAddress'.

    jump : bool, optional
        Jump to the address

    clipboard : bool, optional
        Copy the result to the clipboard. If False, the clipboard is not
        altered. Default is True

    Returns
    -------
    output : str
        Formatted output
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
    addr_str = '0x' + hex(addr)[2:].upper()
    dec = str(c_int32(addr).value)
    dechex = dec + '; //' + addr_str
    dname = strip(name_hr)
    output = dname + ' = ' + dechex

    if jump:
        idaapi.jumpto(addr)

    if out_format == 'hex':
        output = addr_str
    elif out_format == 'dec':
        output = dec
    elif out_format == 'dechex':
        output = dechex
    elif out_format == 'assign':
        pass
    elif isinstance(out_format, int) and out_format > 0:
        output = ('const int ' + dname + ' ').ljust(out_format) + '= ' + dechex
    else:
        raise ValueError('Invalid argument for \'out_format\'.')

    if clipboard is True:
        pyperclip.copy(output)

    return output


def format_here(out_format='assign', clipboard=True):
    inp = encode(ScreenEA(), False, False)
    return decode(inp, out_format, False, clipboard)


def each(addr_list):
    gen = (hex(i) + ': ' + encode(i) for i in addr_list)

    def cont():
        return next(gen)

    return cont


def batch_encode(addr_list, clipboard=True, verbose=True):
    """
    Batch encode a list of addresses

    Parameters
    ----------
    addr_list : iterable or iterator of int
        Sequence of integer addresses to encode

    clipboard : bool, optional
        Copy the result to the clipboard. If False, the clipboard is not
        altered. Default is True

    verbose : bool, optional
        Print information. Default is True

    Returns
    -------
    output : list
        List of formatted symbol names as 'uid+offset'

    Raises
    ------
    TypeError
        If `addr_list` is not a sequence

    ValueError
        If `addr_list` does not contain all integers

    See also
    --------
    encode :
        Encoding function
    """
    if not hasattr(addr_list, '__len__'):
        raise TypeError('Argument \'addr_list\' is not an iterable')
    if not all(map(lambda x: isinstance(x, int), addr_list)):
        raise ValueError('Argument \'addr_list\' may only contain integers')
    output = []
    for addr in addr_list:
        formatted_name = encode(addr, False, False)
        output.append(formatted_name)

    if clipboard is True:
        pyperclip.copy(str(output))

    if verbose:
        print('done')

    return output


def batch_decode(info_list='clipboard', out_format='hex', clipboard=True,
                 verbose=True):
    """
    Batch decode a list of symbol identifiers

    Parameters
    ----------
    info_list : iterable or iterator of str or 'clipboard', optional
        Sequence of string symbol names in the form 'uid+offset' to
        decode. If 'clipboard', load the contents of the clipboard.
        Default is 'clipboard'

    out_format : {'dec', 'hexdec', 'assign'} or int, optional
        Format of the address output. If 'hex', format as hexadecimal.
        If 'dec', format as 32-bit decimal. If 'dechex', format as
        'DecAddress; //HexAddress'. If 'assign', as
        'DemangledName = DecAddress; //HexAddress'. If int, same as
        'assign' but spaces to fill length of int until the '=', e.g. 20
        results in 'DemangledName       = DecAddress; //HexAddress'.

    clipboard : bool, optional
        Copy the result to the clipboard. If False, the clipboard is not
        altered. Default is True

    verbose : bool, optional
        Print information. Default is True

    Returns
    -------
    output : str
        Paragraph of addresses formatted as `out_format`

    Raises
    ------
    TypeError
        If `info_list` is not a sequence

    ValueError
        If `info_list` does not contain all strings

    See also
    --------
    decode :
        Decoding function
    """
    if isinstance(info_list, str) and info_list == 'clipboard':
        info_list = str(pyperclip.paste())
        info_list = info_list.strip('[]').split(',')
        info_list = [il.strip(' "\'') for il in info_list]

    if not hasattr(info_list, '__len__'):
        raise TypeError('Argument \'info_list\' is not an iterable')
    if not all(map(lambda x: isinstance(x, str), info_list)):
        raise ValueError('Argument \'info_list\' may only contain strings')
    output = []
    for info in info_list:
        output.append(decode(info, out_format, False, False))

    output = '\n'.join(output)

    if clipboard is True:
        pyperclip.copy(output)

    if verbose:
        print('done')

    return output
