"""
Miscellaneous utility functions
"""
__all__ = [
    'strip',
]


def strip(line):
    chars = [
        ' ',
        ':',
        '<',
        '>',
        '~',
        '`',
        '\'',
        '_*_',
        '*',
    ]
    for c in chars:
        line = line.replace(c, '_')
    line = line.split('(')[0]
    return line
