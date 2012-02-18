hibernate_vtypes = {
    '_IMAGE_HIBER_HEADER' : [ 0xbc, {
    'Signature' : [ 0x0, ['array', 4, ['unsigned char']]],
    'SystemTime' : [ 0x20, ['_LARGE_INTEGER']],
    'FirstTablePage' : [ 0x58, ['unsigned long']],
} ],
    'MEMORY_RANGE_ARRAY_LINK' : [ 0x10, {
    'NextTable' : [ 0x4, ['unsigned long']],
    'EntryCount' : [ 0xc, ['unsigned long']],
} ],
    'MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, {
    'StartPage' : [ 0x4, ['unsigned long']],
    'EndPage' : [ 0x8, ['unsigned long']],
} ],
    '_MEMORY_RANGE_ARRAY' : [ 0x20, {
    'MemArrayLink' : [ 0x0, ['MEMORY_RANGE_ARRAY_LINK']],
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['MEMORY_RANGE_ARRAY_RANGE']]],
} ],
'_IMAGE_XPRESS_HEADER' : [  0x20 , {
  'u09' : [ 0x9, ['unsigned char']],
  'u0A' : [ 0xA, ['unsigned char']],
  'u0B' : [ 0xB, ['unsigned char']],
} ]
}
