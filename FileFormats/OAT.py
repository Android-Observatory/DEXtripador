#!/usr/bin/python3
# -*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: FileFormats/OAT.py
#   Version: 0.7
######################################################

import os
import sys

from FileWork import *
from DextractorException import *
from FileFormats.DEX import DEXHeader
from utils import *

OAT_MAGIC_TYPE = c_ubyte * 4
OAT_VERSION_TYPE = c_ubyte * 4


class OATClassHeader():
    '''
    Parser for OAT Class Header, here we will have the number
    of compiled methods

    OATClassHeader {
        uint16 status,
        uint16 type,
        uint32 bitmap_size,
        ubyte[bitmap_size] bitmap,
        uint32[variable] methods_offsets
    }
    '''

    kOatClassAllCompiled = 0
    kOatClassSomeCompiled = 1
    kOatClassNoneCompiled = 2

    '''
    Constants, thanks to Lief project by @rh0main
    '''
    STATUS_RETIRED = -2  # Retired, should not be used. Use the newly cloned one instead.
    STATUS_ERROR = -1
    STATUS_NOTREADY = 0
    # Loaded, DEX idx in super_class_type_idx_ and interfaces_type_idx_.
    STATUS_IDX = 1
    STATUS_LOADED = 2  # DEX idx values resolved.
    STATUS_RESOLVING = 3  # Just cloned from temporary class object.
    STATUS_RESOLVED = 4  # Part of linking.
    STATUS_VERIFYING = 5  # In the process of being verified.
    # Compile time verification failed, retry at runtime.
    STATUS_RETRY_VERIFICATION_AT_RUNTIME = 6
    STATUS_VERIFYING_AT_RUNTIME = 7  # Retrying verification at runtime.
    STATUS_VERIFIED = 8  # Logically part of linking; done pre-init.
    STATUS_INITIALIZING = 9  # Class init in progress.
    STATUS_INITIALIZED = 10  # Ready to go.

    def __init__(self, file_pointer):
        '''
        Initializer of OAT header parser,  here
        we will initialize used variables, we will
        use ctypes instead of python types to have
        fixed size types.

        :param file_pointer: integer specifying pointer offset within opened file.
        '''
        self.file_p = file_pointer

        self.status = c_ushort()
        self.type = c_ushort()
        self.bitmap_size = c_uint()
        self.bitmap = None
        self.methods_offsets = None

        self.compiled_methods = 0

        self.header_initialized = False

    def parse_header(self,  offset, file_size):
        self.file_p.seek(offset, FILE_BEGIN)

        self.status = read_file_le(
            self.file_p, USHORT, USHORT_SIZE, self.file_p.tell())

        if self.status.value > OATClassHeader.STATUS_INITIALIZED:
            raise OATClassHeaderIncorrectStatusException(
                "OATClassHeader status incorrect (%d)" % (self.status.value))

        self.type = read_file_le(
            self.file_p, USHORT, USHORT_SIZE, self.file_p.tell())

        if self.type.value > OATClassHeader.kOatClassNoneCompiled:
            raise OATClassHeaderIncorrectTypeException(
                "OATClassHeader type incorrect (%d)" % (self.type.value))

        '''
        The bitmap field represents the compiled methods, each bit of
        the bitmap starting from the least significant bit to the most
        significant bit.
        If type is kOatClassAllCompiled there's no bitmap as all the
        methods have been optimized.
        If type is kOatClassNoneCompiled there's no bitmap, as there aren't
        compiled methods.
        '''
        if self.type.value == OATClassHeader.kOatClassSomeCompiled:
            self.bitmap_size = read_file_le(
                self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
            self.bitmap = (c_ubyte * self.bitmap_size.value)()
            for i in range(self.bitmap_size.value):
                self.bitmap[i] = read_file_le(
                    self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

                # check each byte for compiled methods
                for shifter in range(8):
                    if (1 << shifter) & self.bitmap[i]:
                        self.compiled_methods += 1

        self.methods_offsets = (c_uint * self.compiled_methods)()

        for i in range(self.compiled_methods):
            self.methods_offsets[i] = read_file_le(
                self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
            if self.methods_offsets[i] > file_size:
                raise OffsetOutOfBoundException(
                    "Error, methods_offset[%d] (0x%08X) is out of bound of the file" % (i, self.methods_offsets[i]))

        self.header_initialized = True

    def print_header(self):

        if not self.header_initialized:
            return

        print("\n\t==================================")
        print("\tOAT Class Header")
        print("\t==================================")

        sys.stdout.write("\tStatus: %d (0x%08X)" %
                         (self.status.value, self.status.value))

        if self.status.value == OATClassHeader.STATUS_RETIRED:
            sys.stdout.write("(STATUS_RETIRED)")
        elif self.status.value == OATClassHeader.STATUS_ERROR:
            sys.stdout.write("(STATUS_ERROR)")
        elif self.status.value == OATClassHeader.STATUS_NOTREADY:
            sys.stdout.write("(STATUS_NOTREADY)")
        elif self.status.value == OATClassHeader.STATUS_IDX:
            sys.stdout.write("(STATUS_IDX)")
        elif self.status.value == OATClassHeader.STATUS_LOADED:
            sys.stdout.write("(STATUS_LOADED)")
        elif self.status.value == OATClassHeader.STATUS_RESOLVING:
            sys.stdout.write("(STATUS_RESOLVING)")
        elif self.status.value == OATClassHeader.STATUS_RESOLVED:
            sys.stdout.write("(STATUS_RESOLVED)")
        elif self.status.value == OATClassHeader.STATUS_VERIFYING:
            sys.stdout.write("(STATUS_VERIFYING)")
        elif self.status.value == OATClassHeader.STATUS_RETRY_VERIFICATION_AT_RUNTIME:
            sys.stdout.write("(STATUS_RETRY_VERIFICATION_AT_RUNTIME)")
        elif self.status.value == OATClassHeader.STATUS_VERIFYING_AT_RUNTIME:
            sys.stdout.write("(STATUS_VERIFYING_AT_RUNTIME)")
        elif self.status.value == OATClassHeader.STATUS_VERIFIED:
            sys.stdout.write("(STATUS_VERIFIED)")
        elif self.status.value == OATClassHeader.STATUS_INITIALIZING:
            sys.stdout.write("(STATUS_INITIALIZING)")
        elif self.status.value == OATClassHeader.STATUS_INITIALIZED:
            sys.stdout.write("(STATUS_INITIALIZED)")

        sys.stdout.write('\n')
        sys.stdout.write("\tType: %d" % (self.type.value))

        if self.type.value == OATClassHeader.kOatClassSomeCompiled:
            sys.stdout.write("(kOatClassSomeCompiled)")

            print("\n\tBitmap size: %d" % self.bitmap_size.value)

            sys.stdout.write("\tBitmap (in bits): ")
            for i in range(self.bitmap_size.value):
                sys.stdout.write(
                    '%s' % (bin(self.bitmap[self.bitmap_size.value - 1 - i])[2:].zfill(8)))

        elif self.type.value == OATClassHeader.kOatClassAllCompiled:
            sys.stdout.write("(kOatClassAllCompiled)")

        elif self.type.value == OATClassHeader.kOatClassNoneCompiled:
            sys.stdout.write("(kOatClassNoneCompiled)")

        sys.stdout.write("\n")

        sys.stdout.write("\tMethods offsets: ")
        for i in range(self.compiled_methods):
            sys.stdout.write("0x%08X " % self.methods_offsets[i])

        sys.stdout.write('\n')


class OATDexFileHeader():
    '''
    Parser for OAT Dex File Header, this will contain a header
    of the class DEXHeader

    OATDexFileHeader {
        uint32 dex_file_location_size,
        ubyte[dex_file_location_size] dex_file_location_data,
        uint32 dex_file_location_checksum,
        uint32 dex_file_pointer,
        uint32[DEXHeader.class_defs_size] classes_offsets
    }

    This class can be an array if more than one Dex is inside of the
    oat file, but the array is not sequencial as the next structure
    is stored inside of the second classes_offsets.
    '''

    def __init__(self, file_pointer):
        self.file_p = file_pointer
        self.oat_dex_file_header_offset = file_pointer.tell()
        self.dex_file_location_size = c_uint()
        self.dex_file_location_data = None
        self.dex_file_location_checksum = c_uint()
        self.dex_file_pointer = c_uint()
        self.classes_offsets = None

        self.OATClassHeader = {}

        self.header_initialized = False

        self.dex_file = None

    def print_header(self):
        if not self.header_initialized:
            return

        print("\n==================================")
        print("OAT Dex File Header")
        print("==================================")

        sys.stdout.write("\nDex File Location Size: %d" %
                         self.dex_file_location_size.value)
        sys.stdout.write("\nDex File Location Data: ")

        dex_file_location_data_str = ""

        for i in range(self.dex_file_location_size.value):
            sys.stdout.write("%02X " % self.dex_file_location_data[i])
            dex_file_location_data_str += chr(self.dex_file_location_data[i])

        sys.stdout.write("(%s)" % dex_file_location_data_str)
        sys.stdout.write("\nDex File Location Checksum: %d(0x%08X)" % (
            self.dex_file_location_checksum.value, self.dex_file_location_checksum.value))
        sys.stdout.write("\nDex File Pointer: 0x%08X" %
                         (self.dex_file_pointer.value))

        for i in range(self.dex_file.class_defs_size.value):
            sys.stdout.write("\nClass Number: %d\tClass offset: 0x%08X\n" % (
                i, self.classes_offsets[i]))

            if self.classes_offsets[i] in self.OATClassHeader:
                self.OATClassHeader[self.classes_offsets[i]].print_header()

        sys.stdout.write("\n")

        self.dex_file.print_header()

    def parse_header(self, offset, file_size, oatdata_offset, oat_header_version):
        self.file_p.seek(offset, FILE_BEGIN)

        self.dex_file_location_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        # create the data
        self.dex_file_location_data = (
            c_ubyte * self.dex_file_location_size.value)()

        # read it
        for i in range(self.dex_file_location_size.value):
            self.dex_file_location_data[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

        self.dex_file_location_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.dex_file_pointer = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        if self.dex_file_pointer.value > file_size or (oatdata_offset + self.dex_file_pointer.value) > file_size:
            raise OffsetOutOfBoundException(
                "Error, dex file pointer (0x%08X) is out of bound of the file" % self.dex_file_pointer.value)

        auxiliar_offset = self.file_p.tell()

        ############################################################
        # now point to dex header
        self.file_p.seek(oatdata_offset +
                        self.dex_file_pointer.value, FILE_BEGIN)
        self.dex_file = DEXHeader(self.file_p)

        self.dex_file.parse_header(self.file_p.tell(), file_size)
        ############################################################

        # again move to auxiliar offset
        self.file_p.seek(auxiliar_offset, FILE_BEGIN)

        # Now as we have the class_defs_size
        self.classes_offsets = (c_uint * self.dex_file.class_defs_size.value)()

        next_header = self.file_p.tell() + 8

        for i in range(self.dex_file.class_defs_size.value):
            self.classes_offsets[i] = read_file_le(
                self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

            if self.classes_offsets[i] > file_size or (oatdata_offset + self.classes_offsets[i]) > file_size:
                continue

            # from dextra
            # if ( getOATVer() != '970' && getOATVer() != '570' && getOATVer() != '880' && getOATVer() != '411' )
            if oat_header_version != b"079" and oat_header_version != b"075" and oat_header_version != b"088" and oat_header_version != b"114":
                oatclassheader = OATClassHeader(self.file_p)
                auxiliar_offset = self.file_p.tell()
                try:
                    oatclassheader.parse_header(
                        (oatdata_offset + self.classes_offsets[i]), file_size)
                    # if everything was okay, set as class header
                    self.OATClassHeader[self.classes_offsets[i]
                                        ] = oatclassheader
                except OATClassHeaderIncorrectStatusException as status_exception:
                    Printer.verbose2(
                        "Exception in status parsing OatClassHeader (%s)" % (str(status_exception)))
                except OATClassHeaderIncorrectTypeException as type_exception:
                    Printer.verbose2(
                        "Exception in type parsing OatClassHeader (%s)" % (str(type_exception)))

                # always set previous offset
                self.file_p.seek(auxiliar_offset, FILE_BEGIN)

        self.file_p.seek(next_header, FILE_BEGIN)
        self.header_initialized = True


class OATHeader():
    '''
    Parser for the oatdata section header, this will be used
    to extract parse the headers and finally extract the dex
    file.

    OATFileHeader {
        ubyte[4] magic,
        ubyte[4] version,
        uint32 adler32_checksum,
        uint32 instruction_set,
        uint32 instruction_set_features,
        uint32 dex_file_count,
        uint32 oat_dex_files_offset, # starting from OAT 131
        uint32 executable_offset,
        uint32 interpreter_to_interpreter_bridge_offset,
        uint32 interpreter_to_compiled_code_bridge_offset,
        uint32 jni_dlsym_lookup_offset_,
        uint32 portable_imt_conflict_trampoline_offset,
        uint32 portable_resolution_trampoline_offset,
        uint32 portable_to_interpreter_bridge_offset,
        uint32 quick_generic_jni_trampoline_offset,
        uint32 quick_imt_conflict_trampoline_offset,
        uint32 quick_resolution_trampoline_offset,
        uint32 quick_to_interpreter_bridge_offset,
        int32 image_patch_delta,
        uint32 image_file_location_oat_checksum,
        uint32 image_file_location_oat_data_begin,
        uint32 key_value_store_size,
        ubyte[key_value_store_size] key_value_store
    }
    '''

    # CONSTANTS
    KNONE = 0
    KARM = 1
    KARM64 = 2
    KTHUMB2 = 3
    KX86 = 4
    X86_64 = 5
    KMIPS = 6
    KMIPS64 = 7

    MAGIC_VALUE = b'oat\n'

    VERSION_1 = [b'039', b'045']
    VERSION_2 = [b'062', b'063', b'064', b'075', b'077']
    VERSION_3 = [b'079', b'088', b'114', b'124']
    VERSION_4 = [b'131']
    VERSION_5 = [b'170']

    def __init__(self, file_pointer):
        self.file_p = file_pointer
        self.oatdata_offset = self.file_p.tell()
        self.header_initialized = False

        self.magic = OAT_MAGIC_TYPE()
        self.version = OAT_VERSION_TYPE()
        self.adler32_checksum = c_uint()
        self.instruction_set = c_uint()
        self.instruction_set_features = c_uint()
        self.dex_file_count = c_uint()
        self.oat_dex_files_offset = c_uint()
        self.executable_offset = c_uint()
        self.interpreter_to_interpreter_bridge_offset = c_uint()
        self.interpreter_to_compiled_code_bridge_offset = c_uint()
        self.jni_dlsym_lookup_offset_ = c_uint()
        self.portable_imt_conflict_trampoline_offset = c_uint()
        self.portable_resolution_trampoline_offset = c_uint()
        self.portable_to_interpreter_bridge_offset = c_uint()
        self.quick_generic_jni_trampoline_offset = c_uint()
        self.quick_imt_conflict_trampoline_offset = c_uint()
        self.quick_resolution_trampoline_offset = c_uint()
        self.quick_to_interpreter_bridge_offset = c_uint()
        self.image_patch_delta = c_int()
        self.image_file_location_oat_checksum = c_uint()
        self.image_file_location_oat_data_begin = c_uint()
        self.key_value_store_size = c_uint()
        self.key_value_store = None  # Necessary to initialize with key_value_store_size

        self.OATDexFileHeaders = []

    def print_header(self):

        if not self.header_initialized:
            return

        print("\n==================================")
        print("OAT Header")
        print("==================================")

        sys.stdout.write("\nMagic: ")
        for i in range(ctypes.sizeof(OAT_MAGIC_TYPE)):
            sys.stdout.write("%02X " % self.magic[i])

        sys.stdout.write("(%s)\n" % ctypes.cast(
            self.magic, ctypes.c_char_p).value)

        sys.stdout.write("Version: ")
        for i in range(ctypes.sizeof(OAT_VERSION_TYPE)):
            sys.stdout.write("%02X " % self.version[i])

        sys.stdout.write("(%s)" % ctypes.cast(
            self.version, ctypes.c_char_p).value)

        sys.stdout.write("\nAdler32_checksum: %d(0x%08X)" % (
            self.adler32_checksum.value, self.adler32_checksum.value))
        sys.stdout.write("\nInstruction set: %d" %
                         (self.instruction_set.value))
        sys.stdout.write("\nInstruction set features: %d" %
                         (self.instruction_set_features.value))
        sys.stdout.write("\nDex file count: %d" % (self.dex_file_count.value))
        sys.stdout.write("\nOat dex file offset: 0x%08X" %
                         (self.oat_dex_files_offset.value))
        sys.stdout.write("\nExecutable offset: 0x%08X" %
                         (self.executable_offset.value))
        sys.stdout.write("\nInterpreter to interpreter bridge offset: 0x%08X" % (
            self.interpreter_to_interpreter_bridge_offset.value))
        sys.stdout.write("\nInterpreter to compiled code bridge offset: 0x%08X" % (
            self.interpreter_to_compiled_code_bridge_offset.value))
        sys.stdout.write("\njni dlsym lookup offset: 0x%08X" %
                         (self.jni_dlsym_lookup_offset_.value))
        sys.stdout.write(
            "\nportable imt conflict trampoline offset: 0x%08X" % (self.portable_imt_conflict_trampoline_offset.value))
        sys.stdout.write(
            "\nportable resolution trampoline offset: 0x%08X" % (self.portable_resolution_trampoline_offset.value))
        sys.stdout.write(
            "\nportable to interpreter bridge offset: 0x%08X" % (self.portable_to_interpreter_bridge_offset.value))
        sys.stdout.write(
            "\nquick generic jni trampoline offset: 0x%08X" % (self.quick_generic_jni_trampoline_offset.value))
        sys.stdout.write(
            "\nquick imt conflict trampoline offset: 0x%08X" % (self.quick_imt_conflict_trampoline_offset.value))
        sys.stdout.write(
            "\nquick resolution trampoline offset: 0x%08X" % (self.quick_resolution_trampoline_offset.value))
        sys.stdout.write(
            "\nquick to interpreter bridge offset: 0x%08X" % (self.quick_to_interpreter_bridge_offset.value))

        sys.stdout.write("\nimage patch delta: 0x%08X" %
                         (self.image_patch_delta.value))
        sys.stdout.write("\nimage file location oat checksum: 0x%08X" %
                         (self.image_file_location_oat_checksum.value))
        sys.stdout.write(
            "\nimage file location oat data begin: 0x%08X" % (self.image_file_location_oat_data_begin.value))

        sys.stdout.write("\nkey value store size: %d" %
                         (self.key_value_store_size.value))

        key_value_store_s = ""
        for i in range(self.key_value_store_size.value):
            if (self.key_value_store[i] == 0x00 and i != (self.key_value_store_size.value - 1)):
                key_value_store_s += " "
            else:
                key_value_store_s += chr(self.key_value_store[i])
        sys.stdout.write("\nkey value store: %s\n" % (key_value_store_s))

        for i in range(len(self.OATDexFileHeaders)):
            self.OATDexFileHeaders[i].print_header()

    def _parse_v1(self, offset, file_size):
        '''
        Parse the OAT versions [045, 039]
        :param offset: offset where to start the analysis
        :param file_size: size if it's necessary for offset checks
        :return:
        '''
        self.file_p.seek(offset, FILE_BEGIN)

        self.adler32_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set_features = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.dex_file_count = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        # below OAT 131 oat_dex_files_offset = 0
        self.oat_dex_files_offset = c_uint(0)
        self.executable_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.executable_offset.value > file_size or (self.executable_offset.value + self.oatdata_offset) > file_size:
            raise OffsetOutOfBoundException(
                "Error, executable_offset (0x%08X) is out of bound of the file" % self.executable_offset.value)

        self.interpreter_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                     self.file_p.tell())
        self.interpreter_to_compiled_code_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                       self.file_p.tell())
        self.jni_dlsym_lookup_offset_ = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.portable_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                    self.file_p.tell())
        self.portable_resolution_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())
        self.portable_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())

        self.quick_generic_jni_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                self.file_p.tell())
        self.quick_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                 self.file_p.tell())
        self.quick_resolution_trampoline_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.quick_to_interpreter_bridge_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.image_patch_delta = read_file_le(
            self.file_p, INTEGER, INTEGER_SIZE, self.file_p.tell())
        self.image_file_location_oat_checksum = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                             self.file_p.tell())
        self.image_file_location_oat_data_begin = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.key_value_store_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.key_value_store = (c_ubyte * self.key_value_store_size.value)()

        for i in range(self.key_value_store_size.value):
            self.key_value_store[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

    def _parse_v2(self, offset, file_size):
        '''
        Parse the OAT versions [077, 075, 063, 064, 062]
        :param offset: offset where to start the analysis
        :param file_size: size if it's necessary for offset checks
        :return:
        '''
        self.file_p.seek(offset, FILE_BEGIN)

        self.adler32_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set_features = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.dex_file_count = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        # below OAT 131 oat_dex_files_offset = 0
        self.oat_dex_files_offset = c_uint(0)
        self.executable_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.executable_offset.value > file_size or (self.executable_offset.value + self.oatdata_offset) > file_size:
            raise OffsetOutOfBoundException(
                "Error, executable_offset (0x%08X) is out of bound of the file" % self.executable_offset.value)

        self.interpreter_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                     self.file_p.tell())
        self.interpreter_to_compiled_code_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                       self.file_p.tell())
        self.jni_dlsym_lookup_offset_ = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.portable_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                    self.file_p.tell())
        self.portable_resolution_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())
        self.portable_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())

        self.quick_generic_jni_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                self.file_p.tell())
        self.quick_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                 self.file_p.tell())
        self.quick_resolution_trampoline_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.quick_to_interpreter_bridge_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.key_value_store_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.key_value_store = (c_ubyte * self.key_value_store_size.value)()

        for i in range(self.key_value_store_size.value):
            self.key_value_store[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

    def _parse_v3(self, offset, file_size):
        '''
        Parse the OAT versions [079, 088, 114]
        :param offset: offset where to start the analysis
        :param file_size: size if it's necessary for offset checks
        :return:
        '''
        self.file_p.seek(offset, FILE_BEGIN)

        self.adler32_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set_features = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.dex_file_count = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        # below OAT 131 oat_dex_files_offset = 0
        self.oat_dex_files_offset = c_uint(0)
        self.executable_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.executable_offset.value > file_size or (self.executable_offset.value + self.oatdata_offset) > file_size:
            raise OffsetOutOfBoundException(
                "Error, executable_offset (0x%08X) is out of bound of the file" % self.executable_offset.value)

        self.interpreter_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                     self.file_p.tell())
        self.interpreter_to_compiled_code_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                       self.file_p.tell())
        self.jni_dlsym_lookup_offset_ = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.portable_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                    self.file_p.tell())
        self.portable_resolution_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())
        self.portable_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                  self.file_p.tell())

        self.quick_generic_jni_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                self.file_p.tell())
        self.quick_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                 self.file_p.tell())

        self.image_file_location_oat_checksum = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                             self.file_p.tell())
        self.image_file_location_oat_data_begin = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.key_value_store_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.key_value_store = (c_ubyte * self.key_value_store_size.value)()

        for i in range(self.key_value_store_size.value):
            self.key_value_store[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

    def _parse_v4(self, offset, file_size):
        '''
        Parse the OAT versions [131]
        :param offset: offset where to start the analysis
        :param file_size: size if it's necessary for offset checks
        :return:
        '''
        self.file_p.seek(offset, FILE_BEGIN)

        self.adler32_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set_features = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.dex_file_count = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.oat_dex_files_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.oat_dex_files_offset.value > file_size:
            raise OffsetOutOfBoundException(
                "Error, oat_dex_files_offset (0x%08X) is out of bound of the file" % self.oat_dex_files_offset.value)
        self.executable_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.executable_offset.value > file_size or (self.executable_offset.value + self.oatdata_offset) > file_size:
            raise OffsetOutOfBoundException(
                "Error, executable_offset (0x%08X) is out of bound of the file" % self.executable_offset.value)
        self.interpreter_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                     self.file_p.tell())
        self.interpreter_to_compiled_code_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                       self.file_p.tell())
        self.jni_dlsym_lookup_offset_ = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.quick_generic_jni_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                self.file_p.tell())
        self.quick_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                 self.file_p.tell())

        self.quick_resolution_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.quick_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.image_patch_delta = read_file_le(
            self.file_p, INTEGER, INTEGER_SIZE, self.file_p.tell())

        self.image_file_location_oat_checksum = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                             self.file_p.tell())
        self.image_file_location_oat_data_begin = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.key_value_store_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        print("key value store size: %d" % (self.key_value_store_size.value))

        self.key_value_store = (c_ubyte * self.key_value_store_size.value)()

        for i in range(self.key_value_store_size.value):
            self.key_value_store[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

    def _parse_v5(self, offset, file_size):
        '''
        Parse the OAT versions [170]
        :param offset: offset where to start the analysis
        :param file_size: size if it's necessary for offset checks
        :return:
        '''
        self.file_p.seek(offset, FILE_BEGIN)

        self.adler32_checksum = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.instruction_set_features = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.dex_file_count = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        self.oat_dex_files_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.oat_dex_files_offset.value > file_size:
            raise OffsetOutOfBoundException(
                "Error, oat_dex_files_offset (0x%08X) is out of bound of the file" % self.oat_dex_files_offset.value)
        self.executable_offset = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())
        if self.executable_offset.value > file_size or (self.executable_offset.value + self.oatdata_offset) > file_size:
            raise OffsetOutOfBoundException(
                "Error, executable_offset (0x%08X) is out of bound of the file" % self.executable_offset.value)
        self.jni_dlsym_lookup_offset_ = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.quick_generic_jni_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                self.file_p.tell())
        self.quick_imt_conflict_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                                 self.file_p.tell())

        self.quick_resolution_trampoline_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.quick_to_interpreter_bridge_offset = read_file_le(self.file_p, UINTEGER, UINTEGER_SIZE,
                                                               self.file_p.tell())

        self.key_value_store_size = read_file_le(
            self.file_p, UINTEGER, UINTEGER_SIZE, self.file_p.tell())

        self.key_value_store = (c_ubyte * self.key_value_store_size.value)()

        for i in range(self.key_value_store_size.value):
            self.key_value_store[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

    def parse_header(self, offset, file_size):
        self.file_p.seek(offset, FILE_BEGIN)

        for i in range(ctypes.sizeof(OAT_MAGIC_TYPE)):
            self.magic[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

        if ctypes.cast(self.magic, ctypes.c_char_p).value != OATHeader.MAGIC_VALUE:
            raise IncorrectMagicException(
                "Error, magic header doesn't match expected header %s" % (OATHeader.MAGIC_VALUE))

        for i in range(ctypes.sizeof(OAT_VERSION_TYPE)):
            self.version[i] = read_file_le(
                self.file_p, BYTE, BYTE_SIZE, self.file_p.tell())

        # [045, 039]
        if ctypes.cast(self.version, ctypes.c_char_p).value in OATHeader.VERSION_1:
            self._parse_v1(self.file_p.tell(), file_size)

        # [077, 075, 063, 064, 062]
        elif ctypes.cast(self.version, ctypes.c_char_p).value in OATHeader.VERSION_2:
            self._parse_v2(self.file_p.tell(), file_size)

        # [079, 088, 114]
        elif ctypes.cast(self.version, ctypes.c_char_p).value in OATHeader.VERSION_3:
            self._parse_v3(self.file_p.tell(), file_size)

        # [131]:
        elif ctypes.cast(self.version, ctypes.c_char_p).value in OATHeader.VERSION_4:
            self._parse_v4(self.file_p.tell(), file_size)
        
        # [170]:
        elif ctypes.cast(self.version, ctypes.c_char_p).value in OATHeader.VERSION_5:
            self._parse_v5(self.file_p.tell(), file_size)

        else:
            raise UnsupportedOatVersion("OAT Version analyzed (%s) not supported" % ctypes.cast(
                self.version, ctypes.c_char_p).value)

        # since version 131 oat_dex_file_offset
        # this was introduced inversion android-8.1.0_r1
        if self.oat_dex_files_offset.value != 0:
            OatDexFile = offset + self.oat_dex_files_offset.value
            self.file_p.seek(OatDexFile, FILE_BEGIN)

        for i in range(self.dex_file_count.value):
            oatdexfileheader_aux = OATDexFileHeader(self.file_p)
            oatdexfileheader_aux.parse_header(self.file_p.tell(
            ), file_size, offset, ctypes.cast(self.version, ctypes.c_char_p).value)
            self.OATDexFileHeaders.append(oatdexfileheader_aux)

        self.header_initialized = True
