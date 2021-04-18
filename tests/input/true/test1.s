mov r0 0x5
jge r0 0 4444
var a 999
aaa:
var a aaa
mov r1 0xdead
mov r2 0xdead
jge r0 0 done
jge r0 0 7
mov r3 0xdead
mov r9 a
done:
exit
