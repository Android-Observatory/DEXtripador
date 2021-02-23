#!/usr/bin/python3
# -*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: Dextripador.py
#   Version: 0.7
######################################################

import os
import sys
import ntpath
import argparse
import zlib
import tempfile
import lzma
import gzip

USE_LIEF = False
USE_OWN_PARSER = False

try:
    import lief.ELF
    USE_LIEF = True
except:
    from elfparser_e.python_binding.elf import *
    USE_OWN_PARSER = True
    

from FileWork import *
from utils import *
from DextractorException import *
from FileFormats.OAT import OATHeader
from struct import pack


class Extractor():
    DYNAMIC_SYMBOL_NAME = "oatdata"

    def __init__(self, path_to_odex=""):
        self.path_to_odex = path_to_odex
        self.oatdata_offset = None
        self.oatdata_size = None
        self.oatdata = None
        self.oat_file = None
        self.number_of_dex_files = 0
        self.number_of_optimized_methods = 0
        self.oat_file = None
        self.not_an_elf = False

        # Handle compressed odex files
        if self.path_to_odex.endswith('.xz'):
            fd, fpath = tempfile.mkstemp(suffix='.odex', prefix='dextripador_', dir='/tmp')
            with lzma.open(self.path_to_odex, 'rb') as odexfile:
                written = os.write(fd, odexfile.read())
            if written == 0:
                raise DecompressionException('Cannot decompress file {}'.format(self.path_to_odex))
            self.path_to_odex = fpath
        elif self.path_to_odex.endswith('.gz'):
            fd, fpath = tempfile.mkstemp(suffix='.odex', prefix='dextripador_', dir='/tmp')
            with gzip.open(self.path_to_odex, 'rb') as odexfile:
                written = os.write(fd, odexfile.read())
            if written == 0:
                raise DecompressionException('Cannot decompress file {}'.format(self.path_to_odex))
            self.path_to_odex = fpath


    def __parse_elf(self, path_to_elf):
        Printer.verbose1("Analyzing file %s searching oatdata symbol" % (path_to_elf))

        Printer.verbose2("Checking existence of the file %s" % (path_to_elf))
        if not os.path.exists(path_to_elf):
            Printer.verbose2("File %s does not exist" % (path_to_elf))
            raise FileNotFoundError("File %s doesn't exist or is not correct" % (path_to_elf))
        
        if USE_LIEF:
            elf_binary = lief.ELF.parse(path_to_elf)

            if elf_binary is None:
                raise NotElfFileException("Provided file %s is not an ELF" % (path_to_elf))

            for symbol in list(elf_binary.symbols):
                if symbol.name == Extractor.DYNAMIC_SYMBOL_NAME:
                    Printer.verbose2("%s Found in %s" % (Extractor.DYNAMIC_SYMBOL_NAME, path_to_elf))
                    self.oatdata_offset = symbol.value
                    self.oatdata_size = symbol.size
                    break
        elif USE_OWN_PARSER:
            elf_binary = Elf(path_to_elf)

            if not elf_binary.is_elf():
                raise NotElfFileException("Provided file %s is not an ELF" % (path_to_elf))
                
            for symbol in elf_binary.elf_sym:
                if symbol.st_name == Extractor.DYNAMIC_SYMBOL_NAME:
                    Printer.verbose2("%s Found in %s" % (Extractor.DYNAMIC_SYMBOL_NAME, path_to_elf))
                    self.oatdata_offset = symbol.st_value
                    self.oatdata_size = symbol.st_size
                    break
            
        if self.oatdata_offset is None or self.oatdata_size is None:
            raise OatdataNotFoundException("Error, oatdata symbol not found in ELF (maybe not odex file)")

        Printer.verbose1("Oatdata offset %x - Oatdata size: %x" % (self.oatdata_offset, self.oatdata_size))

    def __parse_oat(self, path_to_oat):
        Printer.verbose1("Analyzing file %s searching oatdata header" % (path_to_oat))

        if not os.path.exists(path_to_oat):
            Printer.verbose2("File %s does not exist" % (path_to_oat))
            raise FileNotFoundError("File %s doesn't exist or is not correct" % (path_to_oat))

        magic_header = []
        file_size = os.stat(path_to_oat).st_size

        if file_size < len(OATHeader.MAGIC_VALUE):
            raise NotOatFileException("File is not an oat file")

        with open(path_to_oat, 'rb') as oat_binary:
            magic_header = oat_binary.read(4)

        if magic_header == OATHeader.MAGIC_VALUE:
            self.oatdata_offset = 0
            self.oatdata_size = file_size

        if self.oatdata_offset is None or self.oatdata_size is None:
            raise OatdataNotFoundException("Error, oatdata header not found in oat file (maybe not oat file)")


    def load(self):
        Printer.print("Starting analysis of odex file")

        try:
            self.__parse_elf(self.path_to_odex)
        except NotElfFileException:
            self.not_an_elf = True

        if self.not_an_elf:
            self.__parse_oat(self.path_to_odex)

        self.oat_file = open(self.path_to_odex, 'rb')

        self.oat_file.seek(self.oatdata_offset, FILE_BEGIN)

        self.oatdata = OATHeader(self.oat_file)

        self.oatdata.parse_header(self.oatdata_offset, os.path.getsize(self.path_to_odex))

        self.number_of_dex_files = self.oatdata.dex_file_count.value

        for i in range(len(self.oatdata.OATDexFileHeaders)):
            for key,oatclass_header in self.oatdata.OATDexFileHeaders[i].OATClassHeader.items():
                self.number_of_optimized_methods += oatclass_header.compiled_methods

        Printer.print("Analysis done correctly")

        if self.path_to_odex.startswith('/tmp/dextripador_') and    \
                self.path_to_odex.endswith('.odex'):
            # Remove files that were decompressed
            os.remove(self.path_to_odex)

    def get_dex_files(self):

        Printer.print("Returning dex files")
        dex_files = []
        for i in range(self.number_of_dex_files):
            actual_oatdexfile = self.oatdata.OATDexFileHeaders[i]
            dex_files.append(actual_oatdexfile.dex_file)

        return dex_files

    def get_dex_names(self):

        Printer.print("Returning dex file names")
        dex_names = []
        for i in range(self.number_of_dex_files):
            actual_oatdexfile = self.oatdata.OATDexFileHeaders[i]

            path_name = ""
            for i in range(actual_oatdexfile.dex_file_location_size.value):
                path_name += chr(actual_oatdexfile.dex_file_location_data[i])
            file_name = ntpath.basename(path_name)

            if '.apk' in file_name:
                file_name = file_name.replace('.apk', '.dex')
            else:
                file_name = file_name + '.dex'

            dex_names.append(file_name)

        return dex_names

    def extract_all_dex(self, recalculate_dex_checksum = False):

        Printer.print("Extracting all the dex files")
        for i in range(self.number_of_dex_files):
            actual_oatdexfile = self.oatdata.OATDexFileHeaders[i]

            actual_dex_file = actual_oatdexfile.dex_file

            # Get the name to extract
            path_name = ""
            for i in range(actual_oatdexfile.dex_file_location_size.value):
                path_name += chr(actual_oatdexfile.dex_file_location_data[i])
            file_name = ntpath.basename(path_name)

            if '.apk' in file_name:
                file_name = file_name.replace('.apk', '.dex')
            else:
                file_name = file_name + '.dex'
                
            # get the offset and size of the dex
            dex_offset = actual_oatdexfile.dex_file_pointer.value + self.oatdata.oatdata_offset
            dex_size = actual_dex_file.file_size.value

            self.oat_file.seek(dex_offset, FILE_BEGIN)

            dex_file_bytes = self.oat_file.read(dex_size)

            output_file = open(file_name, 'wb')


            calculated_dex_checksum = zlib.adler32(dex_file_bytes[12:])

            Printer.verbose1("Calculated dex checksum: 0x%08X - Dex file checksum: 0x%08X" %
                             (calculated_dex_checksum, c_uint(actual_dex_file.checksum.value).value))

            if recalculate_dex_checksum and calculated_dex_checksum != c_uint(actual_dex_file.checksum.value).value:
                Printer.verbose1("Replacing the checksum")
                dex_file_bytes = dex_file_bytes[:8] + pack('I',calculated_dex_checksum) + dex_file_bytes[12:]
                Printer.verbose1("Replaced the checksum")

            output_file.write(dex_file_bytes)
            output_file.close()

        return True

    def extract_dex(self, dex_number, output_name = "", recalculate_dex_checksum = False):

        Printer.print("Extracting dex file %d" % dex_number)
        if dex_number >= self.number_of_dex_files or dex_number < 0:
            raise DexOutOfFoundException("Selected Dex (%d) doesn't exists" % (dex_number))

        actual_oatdexfile = self.oatdata.OATDexFileHeaders[dex_number]

        actual_dex_file = actual_oatdexfile.dex_file

        # Get the name to extract
        if output_name == "":
            # Get the name to extract
            path_name = ""
            for i in range(actual_oatdexfile.dex_file_location_size.value):
                path_name += chr(actual_oatdexfile.dex_file_location_data[i])
            file_name = ntpath.basename(path_name)
            if '.apk' in file_name:
                file_name = file_name.replace('.apk', '.dex')
            else:
                file_name = file_name + '.dex'
        else:
            file_name = output_name

        # get the offset and size of the dex
        dex_offset = actual_oatdexfile.dex_file_pointer.value + self.oatdata.oatdata_offset
        dex_size = actual_dex_file.file_size.value

        self.oat_file.seek(dex_offset, FILE_BEGIN)

        dex_file_bytes = self.oat_file.read(dex_size)

        output_file = open(file_name, 'wb')

        calculated_dex_checksum = zlib.adler32(dex_file_bytes[12:])

        Printer.verbose1("Calculated dex checksum: 0x%08X - Dex file checksum: 0x%08X" % (
        calculated_dex_checksum, c_uint(actual_dex_file.checksum.value).value))

        if recalculate_dex_checksum and calculated_dex_checksum != c_uint(actual_dex_file.checksum.value).value:
            Printer.verbose1("Replacing the checksum")
            dex_file_bytes = dex_file_bytes[:8] + pack('I', calculated_dex_checksum) + dex_file_bytes[12:]
            Printer.verbose1("Replaced the checksum")

        output_file.write(dex_file_bytes)
        output_file.close()

        return True

    def print_all_headers(self):
        Printer.print("Printing all the oatdata headers")
        self.oatdata.print_header()

    def print_all_dex(self):
        Printer.print("Printing all dex file headers\n\n")
        for i in range(self.number_of_dex_files):
            actual_oatdexfile = self.oatdata.OATDexFileHeaders[i]

            actual_dex_file = actual_oatdexfile.dex_file

            actual_dex_file.print_header(num=i)

verbosity_message = '''
Verbosity level:
    -1: no messages
    0: only necessary messages (by default)
    1: verbose level 1
    2: verbose level 2
    3: verbose level 3"
'''

def main():
    extractor = None

    if "--show-credits" in sys.argv:
        print("%s" % credits)
        sys.exit(0)


    parser = argparse.ArgumentParser(
        description="'Dextripador' tool for pasing Odex files and extract dex files from them.\nResearch From UC3M-COSEC & IMDEA Networks.")
    parser.add_argument("-i", "--input", type=str, help="APK to analyze", required=True)
    parser.add_argument("-v", "--verbosity", type=int, help=verbosity_message)
    parser.add_argument("-o", "--output", type=str, help="Output name for the file, by default is extracted from OAT header")
    parser.add_argument("--dextripar", type=int, help="Extract one of the dex files given by index", default=-1)
    parser.add_argument("--dextripar-all", action="store_true", help="Extract all the dex from the file")
    parser.add_argument("--replace-checksum", action="store_true", help="If selected any dextripar option, replace dex checksum for calculated one")
    parser.add_argument("--print-headers", action="store_true", help="Show all the OAT headers (including dex headers)")
    parser.add_argument("--list-dexs", action="store_true", help="List all the internal dex files")
    parser.add_argument("--show-credits", action="store_true", help="Show credits of the tool")
    args = parser.parse_args()

    SET_COMMAND_FLAG(True)

    if args.verbosity == -1:
        SET_COMMAND_FLAG (False)
    elif args.verbosity == 1:
        SET_VERBOSE1(True)
    elif args.verbosity == 2:
        SET_VERBOSE1(True)
        SET_VERBOSE2(True)
    elif args.verbosity == 3:
        SET_VERBOSE1(True)
        SET_VERBOSE2(True)
        SET_VERBOSE3(True)

    extractor = Extractor(args.input)
    extractor.load()

    if args.print_headers:
        extractor.print_all_headers()

    if args.list_dexs:
        extractor.print_all_dex()

    if args.dextripar_all:
        if args.replace_checksum:
            extractor.extract_all_dex(True)
        else:
            extractor.extract_all_dex()

    if args.dextripar >= 0:
        try:
            if args.output:
                extractor.extract_dex(args.dextripar, args.output)
            else:
                extractor.extract_dex(args.dextripar, "")
        except DexOutOfFoundException as dofe:
            Printer.print("Error extracting dex: %s" % (str(dofe)))


if __name__ == '__main__':
    main()
