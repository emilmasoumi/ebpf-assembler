ja lab1 ; PC += 4
ld64 r0 1
ld64 r0 2
lab1:
ld64 r0 3
ld64 r0 4
ja lab1 ; PC += -5
lab2:
ldmapfd r0 5
ja lab2 ; PC += -3
ja lab3 ; PC += 2
ldmapfd r0 6
lab3:
ldmapfd r0 7