ssdt_vtypes = {
    '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 4, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
    '_SERVICE_DESCRIPTOR_ENTRY' : [ 0x10, {
    'KiServiceTable' : [0x0, ['pointer', ['void']]],
    'CounterBaseTable' : [0x4, ['pointer', ['unsigned long']]],
    'ServiceLimit' : [0x8, ['long']],
    'ArgumentTable' : [0xc, ['pointer', ['unsigned char']]],
    }],
}

ssdt_vtypes_2k3 = {
  '_SERVICE_DESCRIPTOR_TABLE' : [ 0x40, {
    'Descriptors' : [0x0, ['array', 2, ['_SERVICE_DESCRIPTOR_ENTRY']]],
    }],
}
