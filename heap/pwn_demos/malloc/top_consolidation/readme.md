<details>
<summary><strong>Description</strong></summary>
<p>

we will again, be focusing on trying to get malloc to reallocate an existing chunk via consolidation. 

**unlike the other instances**, this will be done via consolidating with the top chunk (only modify chunk size, no need to create fake chunk/main_arena -> no required heap leak)...

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

    long *chunk0, *chunk1, *chunk2, *chunk3;

    chunk0 = malloc(0x420);
    chunk1 = malloc(0x80);

    /*VULNERABILITY*/
    chunk0[-1] = ((0x420 + 0x10) + (0x80 + 0x10)) + 0x1; // expand chunk0's size (encompass first two chunks)
    /*VULNERABILITY*/

    free(chunk0); // trigger consolidation
    chunk2 = malloc(0x420); // can padding this depend on purpose
    chunk3 = malloc(0x80); // is the same with chunk1

    printf("chunk3: %p\n", chunk3);
    printf("chunk1 (still in use): %p\n", chunk1);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/malloc/top_consolidation/readme.md

</p>
</details>