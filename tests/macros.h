static struct bpf_insn prog[1000000] = {
BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 1),
BPF_EXIT_INSN(),
};
