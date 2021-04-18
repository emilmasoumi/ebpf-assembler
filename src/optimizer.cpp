/*
  Various optimization algorithms optimizing the eBPF bytecode.
*/

#include "optimizer.h"

/* Dead store elimination */
void dead_store_elim(void) {

}

/* Jump threading */
void jump_threading(void) {

}

/* Peephole optimization */
void peephole_opt(void) {

}

void optimizer(void) {
  dead_store_elim();
  jump_threading();
  peephole_opt();
}
