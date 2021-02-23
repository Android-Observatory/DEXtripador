#!/usr/bin/python3
#-*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: FileFormats/DEX.py
#   Version: 0.7
######################################################

import os
import sys

from FileWork import *
from DextractorException import *

DEX_MAGIC_TYPE = c_ubyte * 8
DEX_SIGNATURE_TYPE = c_ubyte * 20

class DEXHeader():
    '''
        Header of Dex file, it has the next structure:
        DexfileHeader{
            ubyte[8] magic,
            int checksum,
            ubyte[20] signature,
            uint file_size,
            uint header_size,
            uint endian_tag,
            uint link_size,
            uint link_off,
            uint map_off,
            uint string_ids_size,
            uint string_ids_off,
            uint type_ids_size,
            uint type_ids_off,
            uint proto_ids_size,
            uint proto_ids_off,
            uint field_ids_size,
            uint field_ids_off,
            uint method_ids_size,
            uint method_ids_off,
            uint class_defs_size,
            uint class_defs_off,
            uint data_size,
            uint data_off
        }
    '''

    def __init__(self, file_pointer):
        '''
        Initializer of DEX header parser, we will use
        ctypes instead of using python types so we will
        have fixed size types.

        :param file_pointer: integer specifying pointer offset within opened file.
        '''
        self.file_p = file_pointer

        self.magic = DEX_MAGIC_TYPE()
        self.checksum = c_int()
        self.signature = DEX_SIGNATURE_TYPE()
        self.file_size = c_uint()
        self.header_size = c_uint()
        self.endian_tag = c_uint()

        self.link_size = c_uint()
        self.link_off = c_uint()

        self.map_off = c_uint()

        self.string_ids_size = c_uint()
        self.string_ids_off = c_uint()

        self.type_ids_size = c_uint()
        self.type_ids_off = c_uint()

        self.proto_ids_size = c_uint()
        self.proto_ids_off = c_uint()

        self.field_ids_size = c_uint()
        self.field_ids_off = c_uint()

        self.method_ids_size = c_uint()
        self.method_ids_off = c_uint()

        self.class_defs_size = c_uint()
        self.class_defs_off = c_uint()

        self.data_size = c_uint()
        self.data_off = c_uint()

        self.header_initialized = False

    def print_header(self, num = None):
        '''
        Print the parsed DEX header, as different
        DEX files can be within an OAT file, a number
        can be given to specify which one is being printed.

        :param num: DEX header that is being printed.
        '''
        if not self.header_initialized:
            return

        print("\n==================================")
        if num is None:
            print("DEX Header")
        else:
            print("Dex Header [%d]" % (num))
        print("==================================")

        sys.stdout.write("\nMagic: ")
        for i in range(ctypes.sizeof(DEX_MAGIC_TYPE)):
            sys.stdout.write("%02X " % self.magic[i])

        sys.stdout.write("(%s)" % ctypes.cast(self.magic, ctypes.c_char_p).value)

        sys.stdout.write("\nChecksum: %d(0x%08X)" % (self.checksum.value, self.checksum.value))

        sys.stdout.write("\nSignature: ")
        for i in range(ctypes.sizeof(DEX_SIGNATURE_TYPE)):
            sys.stdout.write("%02X " % self.signature[i])

        sys.stdout.write("\nFile Size: %d" % self.file_size.value)
        sys.stdout.write("\nHeader Size: %d" % self.header_size.value)
        sys.stdout.write("\nEndian Tag: %d(0x%08X)" % (self.endian_tag.value, self.endian_tag.value))
        sys.stdout.write("\nLink Size: %d" % (self.link_size.value))
        sys.stdout.write("\nLink Offset: 0x%08X" % (self.link_off.value))
        sys.stdout.write("\nMap Offset: 0x%08X" % (self.map_off.value))
        sys.stdout.write("\nString IDS Size: %d" % (self.string_ids_size.value))
        sys.stdout.write("\nString IDS Offset: 0x%08X" % (self.string_ids_off.value))
        sys.stdout.write("\nType IDS Size: %d" % (self.type_ids_size.value))
        sys.stdout.write("\nType IDS Offset: 0x%08X" % (self.type_ids_off.value))
        sys.stdout.write("\nProto IDS Size: %d" % (self.proto_ids_size.value))
        sys.stdout.write("\nProto IDS Offset: 0x%08X" % (self.proto_ids_off.value))
        sys.stdout.write("\nField IDS Size: %d" % (self.field_ids_size.value))
        sys.stdout.write("\nField IDS Offset: 0x%08X" % (self.field_ids_off.value))
        sys.stdout.write("\nMethod IDS Size: %d" % (self.method_ids_size.value))
        sys.stdout.write("\nMethod IDS Offset: 0x%08X" % (self.method_ids_off.value))
        sys.stdout.write("\nClass Defs Size: %d" % (self.class_defs_size.value))
        sys.stdout.write("\nClass Defs Offset: 0x%08X" % (self.class_defs_off.value))
        sys.stdout.write("\nData Size: %d" % (self.data_size.value))
        sys.stdout.write("\nData Offset: 0x%08X\n" % (self.data_off.value))

    def parse_header(self, offset, file_size):
        '''
        Parsing method for DEX header, checks are done
        in order to detech if some offsets are out of bound
        of the current file.

        :param offset: offset where to start parsing the DEX header.
        :param file_size: file size used for checking offset bounds.
        '''
        self.file_p.seek(offset, 0)

        for i in range(ctypes.sizeof(DEX_MAGIC_TYPE)):
            self.magic[i] = read_file_le(self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

        self.checksum = read_file_le(self.file_p, INTEGER, INTEGER_SIZE, self.file_p.tell())

        for i in range(ctypes.sizeof(DEX_SIGNATURE_TYPE)):
            self.signature[i] = read_file_le(self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

        self.file_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.header_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.endian_tag = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.link_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.link_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.link_off.value > file_size:
            raise OffsetOutOfBoundException("Error, link offset (0x%08X) is out of bound of the file" % self.link_off.value)

        self.map_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.map_off.value > file_size:
            raise OffsetOutOfBoundException("Error, map offset (0x%08X) is out of bound of the file" % self.map_off.value)

        self.string_ids_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.string_ids_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.string_ids_off.value > file_size:
            raise OffsetOutOfBoundException("Error, string ids offset (0x%08X) is out of bound of the file" % self.string_ids_off.value)

        self.type_ids_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.type_ids_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.type_ids_off.value > file_size:
            raise OffsetOutOfBoundException("Error, type ids offset (0x%08X) is out of bound of the file" % self.type_ids_off.value)

        self.proto_ids_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.proto_ids_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.proto_ids_off.value > file_size:
            raise OffsetOutOfBoundException("Error, proto ids offset (0x%08X) is out of bound of the file" % self.proto_ids_off.value)

        self.field_ids_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.field_ids_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.field_ids_off.value > file_size:
            raise OffsetOutOfBoundException("Error, field ids offset (0x%08X) is out of bound of the file" % self.field_ids_off.value)

        self.method_ids_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.method_ids_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.method_ids_off.value > file_size:
            raise OffsetOutOfBoundException("Error, method ids offset (0x%08X) is out of bound of the file" % self.method_ids_off.value)

        self.class_defs_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.class_defs_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.class_defs_off.value > file_size:
            raise OffsetOutOfBoundException("Error, class defs offset (0x%08X) is out of bound of the file" % self.class_defs_off.value)

        self.data_size = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.data_off = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.data_off.value > file_size:
            raise OffsetOutOfBoundException("Error, data offset (0x%08X) is out of bound of the file" % self.data_off.value)

        self.header_initialized = True