#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# Copyright (c) 2020 Facebook

import argparse
import logging
import os.path
import shutil
import subprocess
import sys
import tempfile

hexdump_src_template='''
/* SPDX-License-Identifier: LGPL-2.1+ */
/* Autogenerated source header with byte array for %src_c% BPF program.
 * DO NOT MODIFY by hand, will be overriden by meson build rule.
 */
#pragma once

const unsigned char %buffer_name%[] = {
%hexdump%
};
'''

def clang_compile(clang_exec, clang_flags, src_c, src_h, out_file, target_arch,
        target_triplet=None):
    clang_args = [clang_exec]
    clang_args.extend(clang_flags)
    clang_args.extend([target_arch])

    clang_args.extend([
        '-I.'])

    if target_triplet:
        clang_args.extend([
            '-isystem',
            '/usr/include/{}'.format(target_triplet)])

    clang_args.extend([
        '-idirafter',
        '/usr/local/include',
        '-idirafter',
        '/usr/include'])

    clang_args.extend([src_c])
    clang_args.extend(['-o', out_file])

    logging.debug('Generating LLVM bitcode *.bc:')
    logging.debug('{}'.format(' '.join(clang_args)))
    subprocess.check_call(clang_args)


def llc_compile(llc_exec, llc_flags, in_file, out_file):
    llc_args = [llc_exec]
    llc_args.extend(llc_flags)
    llc_args.extend([out_file, in_file])

    logging.debug('Compiling BPF object file:')
    logging.debug('{}'.format(' '.join(llc_args)))
    subprocess.check_call(llc_args)


def hexdump(in_file, indent):
    ret = ''
    indent_prefix = ' ' * indent
    with open(in_file, 'rb') as in_fd:
        while True:
            octets = in_fd.read(16)
            if not octets:
                break
            # Represent octet as hexadecimal number in range 0x00-0xff,
            # join numbers into a line.
            line = ', '.join(['{:#04x}'.format(o) for o in octets])
            ret += '{}{}'.format(indent_prefix, line)
            indent_prefix = ',\n{}'.format(' ' * indent)
    return ret


def get_default_hexdump_buffer_name(hexdump_file):
    return os.path.splitext(os.path.basename(hexdump_file))[0].replace('-',
            '_') + '_buffer'


def get_arch_clang_flag(arch):
    return '-D__{}__'.format(arch)


def get_target_triplet():
    gcc_exec = None
    try:
        gcc_exec = shutil.which('gcc')
    except shutil.Error as e:
        logging.error('Failed to get which gcc: {}'.format(e))
        return None

    try:
        return subprocess.check_output([gcc_exec, '-dumpmachine'],
                text=True).strip()
    except subprocess.CalledProcessError as e:
        logging.error('Failed to get target triplet: {}'.format(e))
        return None


def gen_hexdump_header_file(in_file, out_file, src_c, hexdump_buffer):
    logging.debug(
    'Generating hexdump for {} source from {} object file'
    .format(src_c, in_file))
    with open(out_file, 'w') as out_file_fd:
        if not hexdump_buffer:
            hexdump_buffer = get_default_hexdump_buffer_name(out_file)

        out_file_fd.write(hexdump_src_template
                .replace("%src_c%", src_c)
                .replace("%buffer_name%", hexdump_buffer)
                .replace("%hexdump%", hexdump(in_file, indent=6)))


def bpf_build(args):
    clang_flags = [
            '-Wno-compare-distinct-pointer-types',
            '-O2',
            '-target',
            'bpf',
            '-emit-llvm',
            '-g',
            '-c',
    ]
    with tempfile.NamedTemporaryFile(mode='rb', suffix='.bc') as clang_out_fd, \
        tempfile.NamedTemporaryFile(mode='rb', suffix='.o') as llc_out_fd:
        clang_compile(clang_exec=args.clang_exec,
                clang_flags=clang_flags, src_c=args.bpf_src_c,
                src_h=args.bpf_src_h, out_file=clang_out_fd.name,
                target_arch=get_arch_clang_flag(args.arch),
                target_triplet=get_target_triplet())

        llc_flags = [
            '-march=bpf',
            '-filetype=obj',
            '-o'
        ]
        llc_compile(llc_exec=args.llc_exec, llc_flags=llc_flags,
        in_file=clang_out_fd.name, out_file=llc_out_fd.name)

        gen_hexdump_header_file(in_file=llc_out_fd.name,
                out_file=args.bpf_hexdump_h,
                src_c=args.bpf_src_c,
                hexdump_buffer=args.bpf_hexdump_buffer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '--clang_exec',
            type=str,
            help='Path to clang exec.')

    parser.add_argument(
            '--llc_exec',
            type=str,
            help='Path to llc exec.')

    parser.add_argument(
            '--bpf_src_h',
            type=str,
            nargs='*',
            help='Path to *.h header of compiled BPF program in systemd tree.')

    parser.add_argument(
            'bpf_src_c',
            type=str,
            help='Path to *.c source of BPF program in systemd source tree. \
                    Relative to invoke directory.')

    parser.add_argument(
            'bpf_hexdump_h',
            type=str,
            help='*.h filename to write byte array representation (hexdump) \
                    of BPF *.o object file.')

    parser.add_argument(
            '--bpf_hexdump_buffer',
            type=str,
            help='Name of unsigned char[] C array storing hexdump. If not \
                    specified, defaults to basename of bpf_hexdump_h plus \
                    `_buffer` suffix, e.g. `hexdump_buffer` for \
                    `hexdump.h`.')

    parser.add_argument(
        '--arch',
        type=str,
        help='Target CPU architecture.',
        default='x86_64')

    args = parser.parse_args();

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    bpf_build(args)
