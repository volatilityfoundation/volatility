pe_vtypes = {
    '_IMAGE_EXPORT_DIRECTORY': [ 0x28, {
    'Base': [ 0x10, ['unsigned int']],
    'NumberOfFunctions': [ 0x14, ['unsigned int']], 
    'NumberOfNames': [ 0x18, ['unsigned int']], 
    'AddressOfFunctions': [ 0x1C, ['unsigned int']], 
    'AddressOfNames': [ 0x20, ['unsigned int']], 
    'AddressOfNameOrdinals': [ 0x24, ['unsigned int']], 
    }],
    '_IMAGE_IMPORT_DESCRIPTOR': [ 0x14, {
    # 0 for terminating null import descriptor
    'OriginalFirstThunk': [ 0x0, ['unsigned int']], 
    'TimeDateStamp': [ 0x4, ['unsigned int']], 
    'ForwarderChain': [ 0x8, ['unsigned int']], 
    'Name': [ 0xC, ['unsigned int']], 
    # If bound this has actual addresses
    'FirstThunk': [ 0x10, ['unsigned int']], 
    }],
    '_IMAGE_THUNK_DATA' : [ 0x4, {
    # Fake member for testing if the highest bit is set
    'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 31, end_bit = 32)]],
    'Function' : [ 0x0, ['pointer', ['void']]], 
    'Ordinal' : [ 0x0, ['unsigned long']], 
    'AddressOfData' : [ 0x0, ['unsigned int']], 
    'ForwarderString' : [ 0x0, ['unsigned int']], 
    }],
    '_IMAGE_IMPORT_BY_NAME' : [ None, { 
    'Hint' : [ 0x0, ['unsigned short']], 
    'Name' : [ 0x2, ['String', dict(length = 128)]], 
    }],
}

pe_vtypes_64 = { 
    '_IMAGE_THUNK_DATA' : [ 0x8, {
    # Fake member for testing if the highest bit is set
    'OrdinalBit' : [ 0x0, ['BitField', dict(start_bit = 63, end_bit = 64)]],
    'Function' : [ 0x0, ['pointer64', ['void']]], 
    'Ordinal' : [ 0x0, ['unsigned long long']], 
    'AddressOfData' : [ 0x0, ['unsigned long long']], 
    'ForwarderString' : [ 0x0, ['unsigned long long']], 
    }],
}