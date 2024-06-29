#define NUM_TRUE_TESTS  33
#define NUM_FALSE_TESTS 21
#define NUM_TESTS NUM_TRUE_TESTS + NUM_FALSE_TESTS

#define TEST1_SIZE 9
static struct bpf_insn test1[TEST1_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0x5),
  BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 4444),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 0xdead),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 0xdead),
  BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 3),
  BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_3, 0xdead),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 99),
  BPF_EXIT_INSN(),
};

#define TEST2_SIZE 11
static struct bpf_insn test2[TEST2_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_3, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_4, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_5, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_6, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_7, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_8, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_10, 0),
};

#define TEST3_SIZE 1
static struct bpf_insn test3[TEST3_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 7),
};

#define TEST4_SIZE 1
static struct bpf_insn test4[TEST4_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -1),
};

#define TEST5_SIZE 1
static struct bpf_insn test5[TEST5_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -0x94),
};

#define TEST6_SIZE 5
static struct bpf_insn test6[TEST6_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 32),
  BPF_ALU32_IMM(BPF_MOV, BPF_REG_2, 8),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 77),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_10, 99),
  BPF_EXIT_INSN(),
};

#define TEST7_SIZE 1
static struct bpf_insn test7[TEST7_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -2),
};

#define TEST8_SIZE 2
static struct bpf_insn test8[TEST8_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0x0001),
  BPF_EXIT_INSN(),
};

#define TEST9_SIZE 2
static struct bpf_insn test9[TEST9_SIZE] = {
  BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
};

#define TEST10_SIZE 3
static struct bpf_insn test10[TEST10_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 3),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_5, 9),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 4),
};

#define TEST11_SIZE 3
static struct bpf_insn test11[TEST11_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 3),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_5, 33),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 333),
};

#define TEST12_SIZE 1
static struct bpf_insn test12[TEST12_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 2147483647),
};

#define TEST13_SIZE 1
static struct bpf_insn test13[TEST13_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -2147483648),
};

#define TEST14_SIZE 3
static struct bpf_insn test14[TEST14_SIZE] = {
  BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_0),
  BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_10),
  BPF_EXIT_INSN(),
};

#define TEST15_SIZE 5
static struct bpf_insn test15[TEST15_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0x0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0x0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 0x0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_8, 0x0),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_9, 0x0),

};

#define TEST16_SIZE 8
static struct bpf_insn test16[TEST16_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 10),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 8),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, -2),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 2),
  BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_4, -24),
  BPF_JMP_A(-3),
  BPF_JMP_REG(BPF_JGE, BPF_REG_0, BPF_REG_1, -4200),
};

#define TEST17_SIZE 4
static struct bpf_insn test17[TEST17_SIZE] = {
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
  BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3),
  BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_0),
  BPF_ALU64_REG(BPF_DIV, BPF_REG_6, BPF_REG_7),
};

#define TEST18_SIZE 2
static struct bpf_insn test18[TEST18_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0x1c7),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 0x1c8),
};

#define TEST19_SIZE 8
static struct bpf_insn test19[TEST19_SIZE] = {
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_3, 2147483647),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -2147483648),
  BPF_LD_IMM64(BPF_REG_10, 2147483647),
  BPF_LD_IMM64(BPF_REG_9, -2147483648),
  BPF_LD_MAP_FD(BPF_REG_8, -2147483648),
};

#define TEST20_SIZE 1
static struct bpf_insn test20[TEST20_SIZE] = {
  BPF_ST_MEM(64, BPF_REG_7, 32767, 492),
};

#define TEST21_SIZE 10
static struct bpf_insn test21[TEST21_SIZE] = {
  BPF_JMP_REG(BPF_JLT, BPF_REG_2, BPF_REG_1, -1),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 64),
  BPF_ALU32_IMM(BPF_MOV, BPF_REG_2, 32),
  BPF_JMP_REG(BPF_JLT, BPF_REG_2, BPF_REG_1, 4),
  BPF_JMP_REG(BPF_JGE, BPF_REG_1, BPF_REG_2, 3),
  BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),
  BPF_ALU32_IMM(BPF_ADD, BPF_REG_2, 1),
  BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_2, -3),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};

#define TEST22_SIZE 2
static struct bpf_insn test22[TEST22_SIZE] = {
  BPF_JMP_A(-1),
  BPF_JMP_A(0),
};

#define TEST23_SIZE 18
static struct bpf_insn test23[TEST23_SIZE] = {
  BPF_JMP_A(4),
  BPF_LD_IMM64(BPF_REG_0, 1),
  BPF_LD_IMM64(BPF_REG_0, 2),
  BPF_LD_IMM64(BPF_REG_0, 3),
  BPF_LD_IMM64(BPF_REG_0, 4),
  BPF_JMP_A(-5),
  BPF_LD_MAP_FD(BPF_REG_0, 5),
  BPF_JMP_A(-3),
  BPF_JMP_A(2),
  BPF_LD_MAP_FD(BPF_REG_0, 6),
  BPF_LD_MAP_FD(BPF_REG_0, 7),
};

#define TEST100_SIZE 25
static struct bpf_insn test100[TEST100_SIZE] = {
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_DIV, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_DIV, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_OR, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_AND, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_AND, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_NEG, BPF_REG_0, 0),
  BPF_ALU64_IMM(BPF_MOD, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_MOD, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_ARSH, BPF_REG_0, -512),
  BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
};

#define TEST101_SIZE 25
static struct bpf_insn test101[TEST101_SIZE] = {
  BPF_ALU32_IMM(BPF_ADD, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_SUB, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_SUB, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_DIV, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_DIV, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_OR, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_AND, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_AND, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_LSH, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_LSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_RSH, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_NEG, BPF_REG_0, 0),
  BPF_ALU32_IMM(BPF_MOD, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_MOD, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_XOR, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_XOR, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_ARSH, BPF_REG_0, -0xbeef),
  BPF_ALU32_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
};

#define TEST102_SIZE 6
static struct bpf_insn test102[TEST102_SIZE] = {
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 16),
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 32),
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 64),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 16),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 32),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 64),
};

#define TEST103_SIZE 30
static struct bpf_insn test103[TEST103_SIZE] = {
  BPF_ATOMIC_OP(16, BPF_ADD, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_ADD, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_ADD, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_AND, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_AND, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_AND, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_OR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_OR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_OR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_XOR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_XOR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_XOR, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_XCHG, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_XCHG, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_XCHG, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(16, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(32, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, -256),
  BPF_ATOMIC_OP(64, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, -256),
};

#define TEST104_SIZE 28
static struct bpf_insn test104[TEST104_SIZE] = {
  BPF_LD_MAP_FD(BPF_REG_0, 8192),
  BPF_LD_IMM64(BPF_REG_0, 8192),
  BPF_LD_ABS(8, 3),
  BPF_LD_ABS(16, 3),
  BPF_LD_ABS(32, 3),
  BPF_LD_ABS(64, 3),
  BPF_LD_IND(8, BPF_REG_1, 8192),
  BPF_LD_IND(16, BPF_REG_1, 8192),
  BPF_LD_IND(32, BPF_REG_1, 8192),
  BPF_LD_IND(64, BPF_REG_1, 8192),
  BPF_LDX_MEM(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(64, BPF_REG_0, BPF_REG_1, 8),
  BPF_ST_MEM(8, BPF_REG_0, 8, 8192),
  BPF_ST_MEM(16, BPF_REG_0, 8, 8192),
  BPF_ST_MEM(32, BPF_REG_0, 8, 8192),
  BPF_ST_MEM(64, BPF_REG_0, 8, 8192),
  BPF_STX_MEM(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(64, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(64, BPF_REG_0, BPF_REG_1, 8),
};

#define TEST105_SIZE 24
static struct bpf_insn test105[TEST105_SIZE] = {
  BPF_JMP_A(8),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JGT, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JGE, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JLT, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JLE, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JLE, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JSET, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JSET, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JSGT, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JSGT, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JSGE, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JSGE, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JSLT, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JSLT, BPF_REG_0, BPF_REG_1, 1024),
  BPF_JMP_IMM(BPF_JSLE, BPF_REG_0, 16384, 1024),
  BPF_JMP_REG(BPF_JSLE, BPF_REG_0, BPF_REG_1, 1024),
  BPF_CALL_REL(64),
};

#define TEST106_SIZE 22
static struct bpf_insn test106[TEST106_SIZE] = {
  BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JGT, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JGT, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JGE, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JGE, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JLT, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JLT, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JLE, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JLE, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JSET, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JSET, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JSGT, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JSGT, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JSGE, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JSGE, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JSLT, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JSLT, BPF_REG_0, BPF_REG_1, 4096),
  BPF_JMP32_IMM(BPF_JSLE, BPF_REG_0, 512, 4096),
  BPF_JMP32_REG(BPF_JSLE, BPF_REG_0, BPF_REG_1, 4096),
};

#define TEST107_SIZE 1
static struct bpf_insn test107[TEST107_SIZE] = {
  BPF_ZEXT_REG(BPF_REG_0),
};

#define TEST108_SIZE 1
static struct bpf_insn test108[TEST108_SIZE] = {
  BPF_EXIT_INSN(),
};

#define TEST109_SIZE 162
static struct bpf_insn test109[TEST109_SIZE] = {
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_DIV, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_DIV, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_OR, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_AND, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_NEG, BPF_REG_0, 0),
  BPF_ALU64_IMM(BPF_MOD, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_MOD, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
  BPF_ALU64_IMM(BPF_ARSH, BPF_REG_0, 128),
  BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_ADD, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_SUB, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_SUB, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_DIV, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_DIV, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_OR, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_AND, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_AND, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_LSH, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_LSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_RSH, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_NEG, BPF_REG_0, 0),
  BPF_ALU32_IMM(BPF_MOD, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_MOD, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_XOR, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_XOR, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_MOV, BPF_REG_0, BPF_REG_1),
  BPF_ALU32_IMM(BPF_ARSH, BPF_REG_0, 128),
  BPF_ALU32_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 16),
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 32),
  BPF_ENDIAN(BPF_TO_LE, BPF_REG_0, 64),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 16),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 32),
  BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 64),
  BPF_ATOMIC_OP(16, BPF_ADD, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_ADD, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_ADD, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_AND, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_AND, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_AND, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_OR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_OR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_OR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_XOR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_XOR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_XOR, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_XCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_XCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_XCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(16, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(32, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_ATOMIC_OP(64, BPF_CMPXCHG, BPF_REG_0, BPF_REG_1, 8),
  BPF_LD_MAP_FD(BPF_REG_0, 128),
  BPF_LD_IMM64(BPF_REG_0, 128),
  BPF_LD_ABS(8, 3),
  BPF_LD_ABS(16, 3),
  BPF_LD_ABS(32, 3),
  BPF_LD_ABS(64, 3),
  BPF_LD_IND(8, BPF_REG_1, 128),
  BPF_LD_IND(16, BPF_REG_1, 128),
  BPF_LD_IND(32, BPF_REG_1, 128),
  BPF_LD_IND(64, BPF_REG_1, 128),
  BPF_LDX_MEM(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_LDX_MEM(64, BPF_REG_0, BPF_REG_1, 8),
  BPF_ST_MEM(8, BPF_REG_0, 8, 128),
  BPF_ST_MEM(16, BPF_REG_0, 8, 128),
  BPF_ST_MEM(32, BPF_REG_0, 8, 128),
  BPF_ST_MEM(64, BPF_REG_0, 8, 128),
  BPF_STX_MEM(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_MEM(64, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(8, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(16, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(32, BPF_REG_0, BPF_REG_1, 8),
  BPF_STX_XADD(64, BPF_REG_0, BPF_REG_1, 8),
  BPF_JMP_A(8),
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 128, 45),
  BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 44),
  BPF_JMP_IMM(BPF_JGT, BPF_REG_0, 128, 43),
  BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_1, 42),
  BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 128, 41),
  BPF_JMP_REG(BPF_JGE, BPF_REG_0, BPF_REG_1, 40),
  BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 128, 39),
  BPF_JMP_REG(BPF_JLT, BPF_REG_0, BPF_REG_1, 38),
  BPF_JMP_IMM(BPF_JLE, BPF_REG_0, 128, 37),
  BPF_JMP_REG(BPF_JLE, BPF_REG_0, BPF_REG_1, 36),
  BPF_JMP_IMM(BPF_JSET, BPF_REG_0, 128, 35),
  BPF_JMP_REG(BPF_JSET, BPF_REG_0, BPF_REG_1, 34),
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 128, 33),
  BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 32),
  BPF_JMP_IMM(BPF_JSGT, BPF_REG_0, 128, 31),
  BPF_JMP_REG(BPF_JSGT, BPF_REG_0, BPF_REG_1, 30),
  BPF_JMP_IMM(BPF_JSGE, BPF_REG_0, 128, 29),
  BPF_JMP_REG(BPF_JSGE, BPF_REG_0, BPF_REG_1, 28),
  BPF_JMP_IMM(BPF_JSLT, BPF_REG_0, 128, 27),
  BPF_JMP_REG(BPF_JSLT, BPF_REG_0, BPF_REG_1, 26),
  BPF_JMP_IMM(BPF_JSLE, BPF_REG_0, 128, 25),
  BPF_JMP_REG(BPF_JSLE, BPF_REG_0, BPF_REG_1, 24),
  BPF_CALL_REL(44),
  BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 128, 22),
  BPF_JMP32_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 21),
  BPF_JMP32_IMM(BPF_JGT, BPF_REG_0, 128, 20),
  BPF_JMP32_REG(BPF_JGT, BPF_REG_0, BPF_REG_1, 19),
  BPF_JMP32_IMM(BPF_JGE, BPF_REG_0, 128, 18),
  BPF_JMP32_REG(BPF_JGE, BPF_REG_0, BPF_REG_1, 17),
  BPF_JMP32_IMM(BPF_JLT, BPF_REG_0, 128, 16),
  BPF_JMP32_REG(BPF_JLT, BPF_REG_0, BPF_REG_1, 15),
  BPF_JMP32_IMM(BPF_JLE, BPF_REG_0, 128, 14),
  BPF_JMP32_REG(BPF_JLE, BPF_REG_0, BPF_REG_1, 13),
  BPF_JMP32_IMM(BPF_JSET, BPF_REG_0, 128, 12),
  BPF_JMP32_REG(BPF_JSET, BPF_REG_0, BPF_REG_1, 11),
  BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 128, 10),
  BPF_JMP32_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 9),
  BPF_JMP32_IMM(BPF_JSGT, BPF_REG_0, 128, 8),
  BPF_JMP32_REG(BPF_JSGT, BPF_REG_0, BPF_REG_1, 7),
  BPF_JMP32_IMM(BPF_JSGE, BPF_REG_0, 128, 6),
  BPF_JMP32_REG(BPF_JSGE, BPF_REG_0, BPF_REG_1, 5),
  BPF_JMP32_IMM(BPF_JSLT, BPF_REG_0, 128, 4),
  BPF_JMP32_REG(BPF_JSLT, BPF_REG_0, BPF_REG_1, 3),
  BPF_JMP32_IMM(BPF_JSLE, BPF_REG_0, 128, 2),
  BPF_JMP32_REG(BPF_JSLE, BPF_REG_0, BPF_REG_1, 1),
  BPF_ZEXT_REG(BPF_REG_0),
  BPF_EXIT_INSN(),
};
