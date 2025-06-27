<details>
<summary><strong>Description</strong></summary>
<p>

both the fastbin and the tcache have checks in place in order to detect double frees...

the thing is, the double free checks are for chunks of those particular bin types. So the tcache double free check will only be able to detect another tcache freed chunk, since it checks for the tcache key...

the fastbin double free check, is that the new chunk to be inserted is not the same as the old fastbin head...

as such, the fastbin double free check cannot detect that a chunk has been inserted into the tcache and vice versa. This is what we are going to leverage...

so basically we are going to insert a chunk into the fastbin, then into the tcache. This will enable us to free the same chunk twice...

> there is another version of this primitive with tcache-unsortebin, you can see it in `house of botcake`...

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

    long *chunk[8];

    for(int i = 0; i < 8; i++) chunk[i] = malloc(0x78); // request size must be in fastbin range in order to work

    for(int i = 0; i < 7; i++) free(chunk[i]); // fill the 0x80 tcache
    free(chunk[7]); // chunk[7] goes to fastbin

    malloc(0x78); // allocate a chunk from the 0x80 tcache to make space for the duplicate chunk

    // VULNERABILITY
    free(chunk[7]); // chunk[7] goes to 0x80 tcache
    // VULNERABILITY

    printf("now that we've inserted the same chunk[7] into both the fastbin and tcache\n");
    printf("now by inserting it into the tcache too, we've changed the next ptr of the fastbin!!!\n");
    printf("depending on what happens, this can cause problems!!!\n");
}
```

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/tcache/tcache_fastbin_double/readme.md

</p>
</details>