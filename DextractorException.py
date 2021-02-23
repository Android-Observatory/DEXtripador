#!/usr/bin/python3
#-*- coding: utf-8 -*-

######################################################
#   Dextripador
#   File: DextractorException.py
#   Version: 0.7
######################################################

class IncorrectMagicException(Exception):
    pass

class OffsetOutOfBoundException(Exception):
    pass

class OatdataNotFoundException(Exception):
    pass

class DexOutOfFoundException(Exception):
    pass

class NotElfFileException(Exception):
    pass

class NotOatFileException(Exception):
    pass

class UnsupportedOatVersion(Exception):
    pass

class OATClassHeaderIncorrectStatusException(Exception):
    pass

class OATClassHeaderIncorrectTypeException(Exception):
    pass

class DecompressionException(Exception):
    pass
