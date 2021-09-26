securejit2
==========

This challenge was part of 0CTF/TCTF Finals 2021.
I played with [r00timentary](https://ctftime.org/team/32783).

Category: `pwnable`

Challenge caption:
```
Yesterday once more.
```


## The Challenge

The players were given a patched version of [`pyast64.py`](https://github.com/benhoyt/pyast64), which was running in a docker container with a custom python3 executable.

Given the Dockerfile, we can create the container ourselves and obtain the custom python3 binary.
Inspecting the binary tells us that it is _not_ PIE:
```bash
$ checksec python3.6
[*] '/usr/bin/python3.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

Apparently, this facilitates writing a ROP chain.
The challenge itself is a Perl script that parses the user input, sets a timer, and executes `pyast64.py` with the user input in the python3 interpreter.

## pyast64

So what does pyast64 do?
It provides a visitor for the python abstract syntax tree (AST) to translate the AST to x86-64 native code.
The user provides the python code, for which pyast64 first creates the AST (via the python `ast` package).
Based on the AST, pyast64's visitor then translates the nodes into assembly code.

Of course, this comes with some limitations.
For instance, strings are not supported.

The patched version of pyast64 in this challenge finally loads the binary code into memory and executes it.
It also adds a function `putc` to write single bytes to `stdout`:

```python
    def compile_putc(self):
        # Insert this into every program so it can call putc() for output
        self.asm.label('putc')
        self.compile_enter()
        self.asm.instr('movq', '$1', '%rax')    # write
        self.asm.instr('movq', '$1', '%rdi')            # stdout
        self.asm.instr('movq', '%rbp', '%rsi')          # address
        self.asm.instr('addq', '$16', '%rsi')
        self.asm.instr('movq', '$1', '%rdx')            # length
        self.asm.instr('syscall')
        self.compile_return(has_arrays=False)
```

## Solution

The `putc` function seems interesting.
However, we can only control the single output byte making it useless unless we find a primitive to jump in the middle of the function.

Nonetheless, playing around with pyast64 reveals some "interesting" behavior.
For example, defined functions are being executed without being called (missing jump/return instructions).
Also, we can issue calls to nonexistent functions:

```python
undefined_function(arg_0)
```

Since the symbol is not defined, the assembly code will have a `call` instruction that simply calls the subsequent instruction.
The `call` instruction will add the return address to the stack, but there is no corresponding `ret` to remove the return address from the stack.
This will leave 8 bytes on the stack.
Since the parameters are passed via the stack, we can simply control the 8 additional bytes.
By repeatedly calling the undefined function, we can place a ROP chain on the stack 8 bytes at a time.

For the ROP chain, we need to consider that we only control the lower four bytes of every entry on the stack (the `push` instruction does not support 64-bit immediates).
The auto-generated ROP chain of [`ropper`](http://scoding.de/ropper/) did not fulfill this requirement.
I adjusted writing the `/bin/sh` string to memory such that it only uses the lower four bytes of every stack entry.

Finally, we simply return and the ROP chain gets triggered.

You can find the exploit in [`x.py`](./x.py).

The flag is: `flag{secure_jit_again_see_you_in_2022}`.
