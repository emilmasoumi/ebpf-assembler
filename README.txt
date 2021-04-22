An eBPF bytecode assembler and compiler that
  * Assembles the bytecode to object code.
  * Compiles the bytecode to C macro preprocessors.

Symbolic names are resolved during parsing and the bytecode is statically
type checked during compile time.

Instructions that have 32-bit equivalents are suffixed with `32`. For example:
`mov32 r0 8` or `jne32 r1 r2 pc+4`. Some instructions cannot perform operations
on certain bit-sizes and will in such cases default to a lower bit-size.

Emitting function calls is not possible, as the implementation of the called
function must be present during compile-time of the assembler. Emitting calls
BPF_EMIT_CALL(FUNC) can instead be invoked after compiling the bytecode to
C preprocessing macros instead of object code. Relevant BPF functions may be
implemented in the future.

A disassembler is provided and can be used with:
./objdump-ebpf <file-with-object-code>

The test folder contains useful utility tools to load eBPF object code into
the kernel (load_ebpf) and to load bytecode defined in C preprocessing macros
into the kernel (load_ebpf_macros).

Refer to bpfc [1] for another assembler/compiler.

--------
Building:

make -j$(nproc)

--------
Usage:
./ebpf-as <source> [options]
options:
    {-O --opt}:
        Employs various compiler optimization strategies to the bytecode.
    {-c --cstruct} <arg>:
        Compiles to preprocessing macros located in a C struct named <arg>.
    {-m --macros}:
        Compiles to preprocessing macros.
    {-o --output} <arg>:
        Outputs to the succeeding argument.
    {-h --help}:
        Prints this usage message.

--------
Example:
```
; comment
mov r1 64
mov32 r2 32
jlt r2 r1 end
jge r1 r2 end
loop:
sub r1 1
add32 r2 1
jle r1 r2 loop
end:
mov r0 0
exit
```

--------
The specification of the instruction set architecture (ISA) is outlined from
the kernel source tree [2][3], the official specification [4] and its
summary [5]:

#### Instruction encoding:

eBPF programs are a sequence of 64-bit instructions and are encoded in the
following byte order by the host:

MSB                                                        LSB
+------------------------+----------------+----+----+--------+
|immediate               |offset          |src |dst |opcode  |
+------------------------+----------------+----+----+--------+

where MSB denotes the most significant bit and LSB denotes the least
significant bit. Each field has the following amount of bits encoded:

* 8 bit opcode (op)
* 4 bit destination register (dst)
* 4 bit source register (src)
* 16 bit offset (off)
* 32 bit immediate (imm)

The 3 LSBs of the opcode field are considered the instruction class:

LD/LDX/ST/STX opcode structure:

MSB         LSB
+----+---+----+
|mde |sz |cls |
+----+---+----+

where the `sz` field specifies the size of the memory location and the `mde`
field is the memory access mode.

ALU/ALU64/JMP opcode structure:

msb        lsb
+----+--+----+
|op  |s |cls |
+----+--+----+

where `op` specifies the ALU/branching instruction and `s` specifies the
source operand. The source operand is an immediate if `s` is 0 or a register
if `s` is 1.

#### ALU instructions:
64-bit:
| Mnemonic     | Pseudocode
|--------------|-------------------------
| add  dst imm | dst += imm
| add  dst src | dst += src
| sub  dst imm | dst -= imm
| sub  dst src | dst -= src
| mul  dst imm | dst *= imm
| mul  dst src | dst *= src
| div  dst imm | dst /= imm
| div  dst src | dst /= src
| or   dst imm | dst \|= imm
| or   dst src | dst \|= src
| and  dst imm | dst &= imm
| and  dst src | dst &= src
| lsh  dst imm | dst <<= imm
| lsh  dst src | dst <<= src
| rsh  dst imm | dst >>= imm (logical)
| rsh  dst src | dst >>= src (logical)
| neg  dst     | dst = ~dst
| mod  dst imm | dst %= imm
| mod  dst src | dst %= src
| xor  dst imm | dst ^= imm
| xor  dst src | dst ^= src
| mov  dst imm | dst = imm
| mov  dst src | dst = src
| arsh dst imm | dst >>= imm (arithmetic)
| arsh dst src | dst >>= src (arithmetic)
-----------------------------------------

32-bit:
| Mnemonic       | Pseudocode
|----------------|-------------------------
| add32  dst imm | dst += imm
| add32  dst src | dst += src
| sub32  dst imm | dst -= imm
| sub32  dst src | dst -= src
| mul32  dst imm | dst *= imm
| mul32  dst src | dst *= src
| div32  dst imm | dst /= imm
| div32  dst src | dst /= src
| or32   dst imm | dst \|= imm
| or32   dst src | dst \|= src
| and32  dst imm | dst &= imm
| and32  dst src | dst &= src
| lsh32  dst imm | dst <<= imm
| lsh32  dst src | dst <<= src
| rsh32  dst imm | dst >>= imm (logical)
| rsh32  dst src | dst >>= src (logical)
| neg32  dst     | dst = ~dst
| mod32  dst imm | dst %= imm
| mod32  dst src | dst %= src
| xor32  dst imm | dst ^= imm
| xor32  dst src | dst ^= src
| mov32  dst imm | dst = imm
| mov32  dst src | dst = src
| arsh32 dst imm | dst >>= imm (arithmetic)
| arsh32 dst src | dst >>= src (arithmetic)
-------------------------------------------

#### Endianess conversion (Byteswap) instructions:
| Mnemonic | Pseudocode
|----------|-------------------
| le16 dst | dst = htole16(dst)
| le32 dst | dst = htole32(dst)
| le64 dst | dst = htole64(dst)
| be16 dst | dst = htobe16(dst)
| be32 dst | dst = htobe32(dst)
| be64 dst | dst = htobe64(dst)
-------------------------------

#### Atomic operations:
| Mnemonic               | Pseudocode
|------------------------|--------------------------------------------
| addx16     dst src off | *(uint16_t *) (dst + off16) += src
| addx32     dst src off | *(uint32_t *) (dst + off16) += src
| addx64     dst src off | *(uint64_t *) (dst + off16) += src
| andx16     dst src off | *(uint16_t *) (dst + off16) &= src
| andx32     dst src off | *(uint32_t *) (dst + off16) &= src
| andx64     dst src off | *(uint64_t *) (dst + off16) &= src
| orx16      dst src off | *(uint16_t *) (dst + off16) |= src
| orx32      dst src off | *(uint32_t *) (dst + off16) |= src
| orx64      dst src off | *(uint64_t *) (dst + off16) |= src
| xorx16     dst src off | *(uint16_t *) (dst + off16) ^= src
| xorx32     dst src off | *(uint32_t *) (dst + off16) ^= src
| xorx64     dst src off | *(uint64_t *) (dst + off16) ^= src
| addfx16    dst src off | src = atomic_fetch_add16(dst + off16, src)
| addfx32    dst src off | src = atomic_fetch_add32(dst + off16, src)
| addfx64    dst src off | src = atomic_fetch_add64(dst + off16, src)
| andfx16    dst src off | src = atomic_fetch_and16(dst + off16, src)
| andfx32    dst src off | src = atomic_fetch_and32(dst + off16, src)
| andfx64    dst src off | src = atomic_fetch_and64(dst + off16, src)
| orfx16     dst src off | src = atomic_fetch_or16(dst + off16, src)
| orfx32     dst src off | src = atomic_fetch_or32(dst + off16, src)
| orfx64     dst src off | src = atomic_fetch_or64(dst + off16, src)
| xorfx16    dst src off | src = atomic_fetch_xor16(dst + off16, src)
| xorfx32    dst src off | src = atomic_fetch_xor32(dst + off16, src)
| xorfx64    dst src off | src = atomic_fetch_xor64(dst + off16, src)
| xchgx16    dst src off | src = atomic_xchg16(dst + off16, src)
| xchgx32    dst src off | src = atomic_xchg32(dst + off16, src)
| xchgx64    dst src off | src = atomic_xchg64(dst + off16, src)
| cmpxchgx16 dst src off | r0 = atomic_cmpxchg16(dst + off16, r0, src)
| cmpxchgx32 dst src off | r0 = atomic_cmpxchg32(dst + off16, r0, src)
| cmpxchgx64 dst src off | r0 = atomic_cmpxchg64(dst + off16, r0, src)
----------------------------------------------------------------------

#### Memory instructions:
| Mnemonic            | Pseudocode
|---------------------|-------------------------------------------
| ldmapfd dst imm     | dst = imm
| ld64    dst imm     | dst = imm
| ldabs8  imm         | r0 = *(uint8_t  *) (skb->data + imm32)
| ldabs16 imm         | r0 = *(uint16_t *) (skb->data + imm32)
| ldabs32 imm         | r0 = *(uint32_t *) (skb->data + imm32)
| ldabs64 imm         | r0 = *(uint64_t *) (skb->data + imm32)
| ldind8  src imm     | r0 = *(uint8_t  *) (skb->data + src + imm32)
| ldind16 src imm     | r0 = *(uint16_t *) (skb->data + src + imm32)
| ldind32 src imm     | r0 = *(uint32_t *) (skb->data + src + imm32)
| ldind64 src imm     | r0 = *(uint64_t *) (skb->data + src + imm32)
| ldx8    dst src off | dst = *(uint8_t  *) (src + off)
| ldx16   dst src off | dst = *(uint16_t *) (src + off)
| ldx32   dst src off | dst = *(uint32_t *) (src + off)
| ldx64   dst src off | dst = *(uint64_t *) (src + off)
| st8     dst off imm | *(uint8_t  *) (dst + off) = imm
| st16    dst off imm | *(uint16_t *) (dst + off) = imm
| st32    dst off imm | *(uint32_t *) (dst + off) = imm
| st64    dst off imm | *(uint64_t *) (dst + off) = imm
| stx8    dst src off | *(uint8_t  *) (dst + off) = src
| stx16   dst src off | *(uint16_t *) (dst + off) = src
| stx32   dst src off | *(uint32_t *) (dst + off) = src
| stx64   dst src off | *(uint64_t *) (dst + off) = src
| stxx8   dst src off | *(uint8_t  *) (dst + off16) += src
| stxx16  dst src off | *(uint16_t *) (dst + off16) += src
| stxx32  dst src off | *(uint32_t *) (dst + off16) += src
| stxx64  dst src off | *(uint64_t *) (dst + off16) += src
--------------------------------------------------------------------

#### Branch instructions:
64-bit:
| Mnemonic         | Pseudocode
|------------------|-------------------------------------------
| ja   off         | PC += off
| jeq  dst imm off | PC += off if dst == imm
| jeq  dst src off | PC += off if dst == src
| jgt  dst imm off | PC += off if dst > imm
| jgt  dst src off | PC += off if dst > src
| jge  dst imm off | PC += off if dst >= imm
| jge  dst src off | PC += off if dst >= src
| jlt  dst imm off | PC += off if dst < imm
| jlt  dst src off | PC += off if dst < src
| jle  dst imm off | PC += off if dst <= imm
| jle  dst src off | PC += off if dst <= src
| jset dst imm off | PC += off if dst & imm
| jset dst src off | PC += off if dst & src
| jne  dst imm off | PC += off if dst != imm
| jne  dst src off | PC += off if dst != src
| jsgt dst imm off | PC += off if dst > imm (signed)
| jsgt dst src off | PC += off if dst > src (signed)
| jsge dst imm off | PC += off if dst >= imm (signed)
| jsge dst src off | PC += off if dst >= src (signed)
| jslt dst imm off | PC += off if dst < imm (signed)
| jslt dst src off | PC += off if dst < src (signed)
| jsle dst imm off | PC += off if dst <= imm (signed)
| jsle dst src off | PC += off if dst <= src (signed)
| call imm         | f(r1, r2, ..., r5); Function call
| rel  imm         | f(r1, r2, ..., r5); Relative function call
| exit             | return r0
---------------------------------------------------------------

32-bit:
| Mnemonic           | Pseudocode
|--------------------|---------------------------------
| jeq32  dst imm off | PC += off if dst == imm
| jeq32  dst src off | PC += off if dst == src
| jgt32  dst imm off | PC += off if dst > imm
| jgt32  dst src off | PC += off if dst > src
| jge32  dst imm off | PC += off if dst >= imm
| jge32  dst src off | PC += off if dst >= src
| jlt32  dst imm off | PC += off if dst < imm
| jlt32  dst src off | PC += off if dst < src
| jle32  dst imm off | PC += off if dst <= imm
| jle32  dst src off | PC += off if dst <= src
| jset32 dst imm off | PC += off if dst & imm
| jset32 dst src off | PC += off if dst & src
| jne32  dst imm off | PC += off if dst != imm
| jne32  dst src off | PC += off if dst != src
| jsgt32 dst imm off | PC += off if dst > imm (signed)
| jsgt32 dst src off | PC += off if dst > src (signed)
| jsge32 dst imm off | PC += off if dst >= imm (signed)
| jsge32 dst src off | PC += off if dst >= src (signed)
| jslt32 dst imm off | PC += off if dst < imm (signed)
| jslt32 dst src off | PC += off if dst < src (signed)
| jsle32 dst imm off | PC += off if dst <= imm (signed)
| jsle32 dst src off | PC += off if dst <= src (signed)
--------------------------------------------------------

#### Special instructions:
| Mnemonic | Pseudocode
|----------|-----------------------------------------
| zext dst | mov32 dst; explicitly zero extending dst
-----------------------------------------------------

--------
References:
[1]: https://www.systutorials.com/docs/linux/man/8-bpfc/
[2]: https://github.com/torvalds/linux/blob/master/include/linux/filter.h
[3]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
[4]: https://www.kernel.org/doc/Documentation/networking/filter.txt
[5]: https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
