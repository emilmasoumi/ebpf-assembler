; Testing the entire instruction set.

;;;; ALU instructions:
; 64-bit:

add  r0 128
add  r0 r1
sub  r0 128
sub  r0 r1
mul  r0 128
mul  r0 r1
div  r0 128
div  r0 r1
or   r0 128
or   r0 r1
and  r0 128
and  r0 r1
lsh  r0 128
lsh  r0 r1
rsh  r0 128
rsh  r0 r1
neg  r0
mod  r0 128
mod  r0 r1
xor  r0 128
xor  r0 r1
mov  r0 128
mov  r0 r1
arsh r0 128
arsh r0 r1

; 32-bit:

add32  r0 128
add32  r0 r1
sub32  r0 128
sub32  r0 r1
mul32  r0 128
mul32  r0 r1
div32  r0 128
div32  r0 r1
or32   r0 128
or32   r0 r1
and32  r0 128
and32  r0 r1
lsh32  r0 128
lsh32  r0 r1
rsh32  r0 128
rsh32  r0 r1
neg32  r0
mod32  r0 128
mod32  r0 r1
xor32  r0 128
xor32  r0 r1
mov32  r0 128
mov32  r0 r1
arsh32 r0 128
arsh32 r0 r1

;;;; Endianess conversion (Byteswap) instructions:

le16 r0
le32 r0
le64 r0
be16 r0
be32 r0
be64 r0

;;;; Atomic operations:

addx16     r0 r1 8
addx32     r0 r1 8
addx64     r0 r1 8
andx16     r0 r1 8
andx32     r0 r1 8
andx64     r0 r1 8
orx16      r0 r1 8
orx32      r0 r1 8
orx64      r0 r1 8
xorx16     r0 r1 8
xorx32     r0 r1 8
xorx64     r0 r1 8
addfx16    r0 r1 8
addfx32    r0 r1 8
addfx64    r0 r1 8
andfx16    r0 r1 8
andfx32    r0 r1 8
andfx64    r0 r1 8
orfx16     r0 r1 8
orfx32     r0 r1 8
orfx64     r0 r1 8
xorfx16    r0 r1 8
xorfx32    r0 r1 8
xorfx64    r0 r1 8
xchgx16    r0 r1 8
xchgx32    r0 r1 8
xchgx64    r0 r1 8
cmpxchgx16 r0 r1 8
cmpxchgx32 r0 r1 8
cmpxchgx64 r0 r1 8

;;;; Memory instructions:

ldmapfd r0 128
ld64    r0 128
ldabs8  3
ldabs16 3
ldabs32 3
ldabs64 3
ldind8  r1 128
ldind16 r1 128
ldind32 r1 128
ldind64 r1 128
ldx8    r0 r1 8
ldx16   r0 r1 8
ldx32   r0 r1 8
ldx64   r0 r1 8
st8     r0 8 128
st16    r0 8 128
st32    r0 8 128
st64    r0 8 128
stx8    r0 r1 8
stx16   r0 r1 8
stx32   r0 r1 8
stx64   r0 r1 8
stxx8   r0 r1 8
stxx16  r0 r1 8
stxx32  r0 r1 8
stxx64  r0 r1 8

;;;; Branch instructions:
; 64-bit:
ja   8
jeq  r0 128 done
jeq  r0 r1 done
jgt  r0 128 done
jgt  r0 r1 done
jge  r0 128 done
jge  r0 r1 done
jlt  r0 128 done
jlt  r0 r1 done
jle  r0 128 done
jle  r0 r1 done
jset r0 128 done
jset r0 r1 done
jne  r0 128 done
jne  r0 r1 done
jsgt r0 128 done
jsgt r0 r1 done
jsge r0 128 done
jsge r0 r1 done
jslt r0 128 done
jslt r0 r1 done
jsle r0 128 done
jsle r0 r1 done
;call 44
rel  44

; 32-bit:
jeq32  r0 128 done
jeq32  r0 r1 done
jgt32  r0 128 done
jgt32  r0 r1 done
jge32  r0 128 done
jge32  r0 r1 done
jlt32  r0 128 done
jlt32  r0 r1 done
jle32  r0 128 done
jle32  r0 r1 done
jset32 r0 128 done
jset32 r0 r1 done
jne32  r0 128 done
jne32  r0 r1 done
jsgt32 r0 128 done
jsgt32 r0 r1 done
jsge32 r0 128 done
jsge32 r0 r1 done
jslt32 r0 128 done
jslt32 r0 r1 done
jsle32 r0 128 done
jsle32 r0 r1 done

;;;; Special instructions:
zext r0

done:
;;;; Branch instruction exit:
exit
