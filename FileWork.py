#!/usr/bin/python3
#-*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: FileWork.py
#   Version: 0.7
######################################################

import ctypes
from ctypes import c_int
from ctypes import c_uint
from ctypes import c_short
from ctypes import c_ushort
from ctypes import c_byte
from ctypes import c_ubyte
from ctypes import c_float
from ctypes import c_long
from ctypes import c_double
import struct


FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

# FORMATS AND SIZES
INTEGER = "i"
INTEGER_SIZE = ctypes.sizeof(c_int())

UINTEGER = "I"
UINTEGER_SIZE = ctypes.sizeof(c_uint())

SHORT = "h"
SHORT_SIZE = ctypes.sizeof(c_short())

USHORT = "H"
USHORT_SIZE = ctypes.sizeof(c_ushort())

BYTE = "B"
BYTE_SIZE = ctypes.sizeof(c_ubyte())

FLOAT = "f"
FLOAT_SIZE = ctypes.sizeof(c_float())

LONG = "l"
LONG_SIZE = ctypes.sizeof(c_long())

DOUBLE = "d"
DOUBLE_SIZE = ctypes.sizeof(c_double())

def read_file(file_p, format, size, offset, endianess = '>'):
    little_endian_format = endianess + format
    file_p.seek(offset, FILE_BEGIN)

    buf = file_p.read(size)
    value = struct.unpack(little_endian_format, buf)[0]

    if format == INTEGER:
        return c_int(value)
    elif format == UINTEGER:
        return c_uint(value)
    elif format == SHORT:
        return c_short(value)
    elif format == USHORT:
        return c_ushort(value)
    elif format == BYTE:
        return c_ubyte(value)
    elif format == FLOAT:
        return c_float(value)
    elif format == LONG:
        return c_long(value)
    elif format == DOUBLE:
        return c_double(value)


def read_file_le(file_p, format, size, offset):
    return read_file(file_p, format, size, offset, endianess='<')

def read_file_be(file_p, format, size, offset):
    return read_file(file_p, format, size, offset, endianess='>')

def read_string_no_modify_offset(file_p, offset):
    previous_offset = file_p.tell()
    return_string = ""

    file_p.seek(offset, 0)

    string_length = file_p.read(1)


    for i in range(string_length[0]):
        byte_value = file_p.read(1)
        return_string += chr(byte_value[0])


    file_p.seek(previous_offset, 0)

    return return_string
