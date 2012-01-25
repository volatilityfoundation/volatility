# SSDT structures for all x86 profiles *except* Win 2003 Server
ssdt_vtypes = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 4, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
    '_SERVICE_DESCRIPTOR_ENTRY' : [ 0x10, {
    'KiServiceTable' : [0x0, ['pointer', ['void']]],
    'CounterBaseTable' : [0x4, ['pointer', ['unsigned long']]],
    'ServiceLimit' : [0x8, ['unsigned long']],
    'ArgumentTable' : [0xc, ['pointer', ['unsigned char']]],
    }],
}

# SSDT structures for Win 2003 Server x86
ssdt_vtypes_2k3 = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x20, {
    'Descriptors' : [0x0, ['array', 2, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
}

# SSDT structures for x64
ssdt_vtypes_64 = { 
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 2, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
    '_SERVICE_DESCRIPTOR_ENTRY' : [ 0x20, {
    'KiServiceTable' : [0x0, ['pointer64', ['void']]],
    'CounterBaseTable' : [0x8, ['pointer64', ['unsigned long']]],
    'ServiceLimit' : [0x10, ['unsigned long long']],
    'ArgumentTable' : [0x18, ['pointer64', ['unsigned char']]],
    }],
}