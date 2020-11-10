import struct


def UInt32(value):
    """Encode a 32-bit integer value"""

    # return value.to_bytes(4, 'big')
    return struct.pack(">L", value)


def UInt64(value):
    """Encode a 64-bit integer value"""

    # return value.to_bytes(8, 'big')
    return struct.pack(">Q", value)

def int64_from_bytes(value):
    """Encode a 64-bit integer value"""

    # return value.to_bytes(8, 'big')
    return struct.unpack(">Q", value)[0]


def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

