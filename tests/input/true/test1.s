mov r0 0x5
jge r0 0 4444
mov r1 0xdead
mov r2 0xdead
jge r0 0 done
jge r1 0 done
mov r3 0xdead
mov r9 99
done:
exit
