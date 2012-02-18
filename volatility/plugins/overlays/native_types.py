import copy

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.
x86_native_types = {
    'int' : [4, '<i'],
    'long': [4, '<i'],
    'unsigned long' : [4, '<I'],
    'unsigned int' : [4, '<I'],
    'address' : [4, '<I'],
    'char' : [1, '<c'],
    'unsigned char' : [1, '<B'],
    'unsigned short int' : [2, '<H'],
    'unsigned short' : [2, '<H'],
    'unsigned be short' : [2, '>H'],
    'short' : [2, '<h'],
    'long long' : [8, '<q'],
    'unsigned long long' : [8, '<Q'],
    }

x64_native_types = copy.deepcopy(x86_native_types)
x64_native_types['address'] = [8, '<Q']
