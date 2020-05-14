#!/usr/bin/env python3
'''

Created by Rafal Wadolowski <rwadolowski@cloudferro.com>
Copyright (C) 2020 CloudFerro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

'''
import logging
import os
import sys
import argparse
import struct
import crc32c

_int1 = "<b"
s_int1 = 1
_uint32 = "<H"
s_uint32 = 4
_uint64 = "<Q"
s_uint64 = 8
_int64 = "<q"
s_int64 = 8
_int32 = "<i"
s_int32 = 4
_double = "<d"
s_double = 8

l = logging.getLogger()
l.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
l.addHandler(handler)


def decode_superblock(bl):
    i=0
    version,i = int1_decode(bl,i)
    l.info(f"Superblock decode version {str(version)}")
    if version!=8:
        l.error("Version not supported, only supported is 8")
        exit(1)
    compat_version,i = int1_decode(bl,i)
    l.info(f"superblock decode compat_version {str(compat_version)}")
    if compat_version!=5:
        l.error("Compat version in rgw_bucket_dir_entry changed")
        exit(1)
    superblock_size,i = uint32_decode(bl,i)
    l.info(f"superblock_size {str(superblock_size)}")
    cluster_fsid,i = decode_uuid(bl,i)
    l.info(f"cluster fsid {cluster_fsid}")
    id,i = int32_decode(bl,i)
    l.info(f"my ID {str(id)}")
    cur_epoch,i = int32_decode(bl,i)
    l.info(f"current epoch {str(cur_epoch)}")
    oldest_map,i = int32_decode(bl,i)
    l.info(f"oldest_map {str(oldest_map)}")
    newest_map,i = int32_decode(bl,i)
    l.info(f"newest_map {str(newest_map)}")
    weight,i = double_decode(bl,i)
    l.info(f"weight {str(weight)}")
    compat_features,i = decode_compat_features(bl,i)
    l.info(f"Compat featuers {str(compat_features)}")
    clean_thru,i = int32_decode(bl,i)
    l.info(f"clean_thru epoch {str(clean_thru)}")
    mounted,i = int32_decode(bl,i)
    l.info(f"mounted epoch {str(mounted)}")
    osd_fsid,i = decode_uuid(bl,i)
    l.info(f"osd fsid {osd_fsid}")
    last_map_marked_full,i = uint32_decode(bl,i)
    l.info(f"last_map_marked_full epoch {str(last_map_marked_full)}")
    pool_last_map_marked_full,i = map_decode_pool_last_map_marked_full(bl,i)
    l.info(f"pool_last_map_marked_full {str(pool_last_map_marked_full)}")
    l.info(f"End of superblock. Position of iterator = {str(i)}")


def decode_uuid(bl,i):
    uuid_size = 16
    id = struct.unpack_from(string_decode_format(uuid_size),bl,i)[0]
    i+=uuid_size
    return "".join("{:02x}".format(c) for c in id),i


def decode_compat_features(bl,i):
    compat,i = decode_featureset(bl,i)
    ro_compat,i = decode_featureset(bl,i)
    incompat,i = decode_featureset(bl,i)
    return [compat,ro_compat,incompat],i


def decode_featureset(bl,i):
    mask,i = uint64_decode(bl,i)
    features,i = map_decode_feature_names(bl,i)
    return {'mask': mask, 'features': features},i


def map_decode_pool_last_map_marked_full(bl,i):
    map_size,i = get_map_size(bl,i)
    pl = []
    for j in range(0,map_size):
        temp = {}
        temp['id'],i = int64_decode(bl,i)
        temp['epoch'],i = uint32_decode(bl,i)
        pl.append(temp)
    return pl,i


def map_decode_feature_names(bl,i):
    map_size,i = get_map_size(bl,i)
    fn = []
    for j in range(0,map_size):
        temp = {}
        temp['id'],i = uint64_decode(bl,i)
        temp['name'],i = string_decode(bl,i)
        fn.append(temp)
    return fn,i


def get_map_size(bufferlist, i):
    map_size = struct.unpack_from(_uint32,bufferlist,i)[0]
    i+=s_uint32
    return map_size,i


def set_string_decode(bufferlist,i):
    s = []
    set_size = struct.unpack_from(_uint32,bufferlist,i)[0]
    i+=s_uint32
    for j in range(0,set_size):
        temp,i = string_decode(bufferlist,i)
    return s,i


def uint32_decode(bufferlist, i):
    value = struct.unpack_from(_uint32,bufferlist,i)[0]
    i+=s_uint32
    return value,i

def double_decode(bufferlist, i):
    value = struct.unpack_from(_double,bufferlist,i)[0]
    i+=s_double
    return value,i

def uint64_decode(bufferlist, i):
    value = struct.unpack_from(_uint64,bufferlist,i)[0]
    i+=s_uint64
    return value,i


def int64_decode(bufferlist, i):
    value = struct.unpack_from(_int64,bufferlist,i)[0]
    i+=s_int64
    return value,i

def int32_decode(bufferlist, i):
    value = struct.unpack_from(_int32,bufferlist,i)[0]
    i+=s_int32
    return value,i


def int1_decode(bufferlist, i):
    value = struct.unpack_from(_int1,bufferlist,i)[0]
    i+=s_int1
    return value,i


def string_decode(bufferlist, i):
    size = struct.unpack_from(_uint32,bufferlist,i)[0]
    i+=s_uint32
    text = struct.unpack_from(string_decode_format(size),bufferlist,i)[0]
    i+=size
    return text,i


def string_decode_format(size):
    return f"<{str(size)}s"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--drive", help="Drive to analyze", action="store", dest='drive')
    args = parser.parse_args()
    if args.drive is None:
        l.error("Error, no arguments passed")
        exit(1)
    dev = os.open(args.drive, os.O_RDONLY)
    os.lseek(dev,0x10000,os.SEEK_SET)
    bl = os.read(dev,0x1000)
    decode_superblock(bl)
    chksum = hex(crc32c.crc32(bl) ^ 0xffffffff)
    l.info(f"Calculated crc32c sum for superblock {str(chksum).rstrip('L')}")
    exit(0)


if __name__ == '__main__':
    main()

