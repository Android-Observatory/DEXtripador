#!/usr/bin/python3
# -*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: FileFormats/VDEX.py
#   Version: 0.7
######################################################

import os
import sys

from FileWork import *
from DextractorException import *
from FileFormats.DEX import DEXHeader

VDEX_MAGIC_TYPE = c_ubyte * 4
VDEX_VERIFIER_DEPS_VERSION_TYPE = c_ubyte * 4
VDEX_DEX_SECTION_VERSION_TYPE = c_ubyte * 4


class VDEXFile():
    '''
    Parser for VDEX File Header, in this file
    we will find the DEX files after OAT version
    124 (Android 8.0).

    VDEXFile {
        uint8_t magic_[4]
        uint8_t verifier_deps_version_[4]
        uint8_t dex_section_version_[4]
        uint32_t number_of_dex_files_
        uint32_t verifier_deps_size_
        uint32_t bootclasspath_checksums_size_
        uint32_t class_loader_context_size_
    }
    '''

    def __init__(self, file_pointer):
        self.file_p = file_pointer
        self.header_initialized = False
        self.dex_file = None

        self.magic = VDEX_MAGIC_TYPE()
        self.verifier_deps_version = VDEX_VERIFIER_DEPS_VERSION_TYPE()
        self.dex_section_version = VDEX_DEX_SECTION_VERSION_TYPE()
        self.number_of_dex_files = c_uint()
        self.verifier_deps_size = c_uint()
        self.bootclasspath_checksums_size = c_uint()
        self.class_loader_context_size = c_uint()

    def print_header(self):
        if not self.header_initialized:
            return

        print("\n==================================")
        print("VEX File Header")
        print("==================================")

        sys.stdout.write("\nVDEX Magic: ")

        for i in range(ctypes.sizeof(VDEX_MAGIC_TYPE)):
            sys.stdout.write("%02X " % (self.magic[i]))

        sys.stdout.write("(%s)\n" % ctypes.cast(
            self.magic, ctypes.c_char_p).value)

        sys.stdout.write("\nVerifier Deps Version: ")

        for i in range(ctypes.sizeof(VDEX_VERIFIER_DEPS_VERSION_TYPE)):
            sys.stdout.write("%02X " % (self.verifier_deps_version[i]))

        sys.stdout.write("(%s)\n" % ctypes.cast(
            self.verifier_deps_version, ctypes.c_char_p).value)

        sys.stdout.write("\nDEX Section Version: ")

        for i in range(ctypes.sizeof(VDEX_DEX_SECTION_VERSION_TYPE)):
            sys.stdout.write("%02X " % (self.dex_section_version[i]))

        sys.stdout.write("(%s)" % ctypes.cast(
            self.dex_section_version, ctypes.c_char_p).value)

        sys.stdout.write("\nNumber of DEX files: %d" %
                         (self.number_of_dex_files.value))

        sys.stdout.write("\nVerifier Deps Size: %d" %
                        (self.verifier_deps_size.value))
        
        sys.stdout.write("\nBootclasspath checksums size: %d" % 
                        (self.bootclasspath_checksums_size.value))
        
        sys.stdout.write("\nClass Loader Context Size: %d" %
                        (self.class_loader_context_size.value))
        
    def parse_header(self, offset, file_size):
        self.file_p.seek(offset, FILE_BEGIN)

        for i in range(ctypes.sizeof(VDEX_MAGIC_TYPE)):
            self.magic[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())
        
        for i in range(ctypes.sizeof(VDEX_VERIFIER_DEPS_VERSION_TYPE)):
            self.verifier_deps_version[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())
        
        for i in range(ctypes.sizeof(VDEX_DEX_SECTION_VERSION_TYPE)):
            self.dex_section_version[i] = read_file_le( 
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())
        
        self.number_of_dex_files = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        
        self.verifier_deps_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        
        self.bootclasspath_checksums_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.class_loader_context_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())