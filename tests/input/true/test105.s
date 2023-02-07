;;;; Branch instructions:
; 64-bit:
ja   8
jeq  r0 16384 1024
jeq  r0 r1 1024
jgt  r0 16384 1024
jgt  r0 r1 1024
jge  r0 16384 1024
jge  r0 r1 1024
jlt  r0 16384 1024
jlt  r0 r1 1024
jle  r0 16384 1024
jle  r0 r1 1024
jset r0 16384 1024
jset r0 r1 1024
jne  r0 16384 1024
jne  r0 r1 1024
jsgt r0 16384 1024
jsgt r0 r1 1024
jsge r0 16384 1024
jsge r0 r1 1024
jslt r0 16384 1024
jslt r0 r1 1024
jsle r0 16384 1024
jsle r0 r1 1024
;call 64
rel  64