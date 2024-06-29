start:
  jlt r2 r1 start
  mov r1 64
  mov32 r2 32
  jlt r2 r1 end ; end = |PC..end| = 4 ; PC += 4 = 4 + 4 = 8
  jge r1 r2 end ; end = |PC..end| = 3 ; PC += 3 = 5 + 3 = 8
loop:
  sub r1 1
  add32 r2 1
  jle r1 r2 loop  ; loop = |loop..PC| - c = -2 - 1 ; PC += -3 = 8 - 3 = 5
end:
  mov r0 0
  exit
epilogue:
