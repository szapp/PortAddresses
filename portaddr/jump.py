"""
Jump utilities
"""
from __future__ import print_function
import idaapi

__all__ = [
    'fncstart',
    'fncend',
]


def fncstart(addr, before=False):
    """
    Jump to the start of a function given an address inside the function

    Parameters
    ----------
    addr : int
        Memory address within the function

    before : bool, optional
        If True, jump to the last instruction before the start of the
        function. Jump to the first instruction of the function
        otherwise. Default is False

    Raises
    ------
    ValueError
        If `addr` is not within a function
    """
    fnc = idaapi.get_func(addr)
    if not fnc:
        raise ValueError
    if before:
        idaapi.jumpto(fnc.startEA-1)  # Scroll above the function name
    else:
        idaapi.jumpto(fnc.startEA)


def fncend(addr):
    """
    Jump to the end of a function given an address inside the function

    Parameters
    ----------
    addr : int
        Memory address within the function

    Raises
    ------
    ValueError
        If `addr` is not within a function
    """
    fnc = idaapi.get_func(addr)
    if not fnc:
        raise ValueError
    idaapi.jumpto(fnc.endEA)
