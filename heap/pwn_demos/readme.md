## Primitives

Various "pure (heap's) primitives" we can (ab)use for futher exploitation.

### Malloc

<details>
<summary><strong>Overlapping chunk via consolidation</strong></summary>
<p>

- **Foward consolidation**
	- [docs](/heap/pwn_demos/malloc/foward_consolidation/readme.md)
	> using forward consolidation to get overlapping memory...

- **Backward consolidation**
	- [docs](/heap/pwn_demos/malloc/backward_consolidation/readme.md)
	> using back consolidation to reallocate a chunk that wasn't freed...

- **Overlapping consolidation**
	- [docs](/heap/pwn_demos/malloc/overlapping_consolidation/readme.md)
	> using consolidation to reallocate a chunk that wasn't freed...

- **Top consolidation**
	- [docs](/heap/pwn_demos/malloc/top_consolidation/readme.md)
	> using top chunk consolidation to reallocate a chunk that wasn't freed...

- **Overlapping mmap**
	- link
	> abc

</p>
</details>

<details>
<summary><strong>Unlinking</strong></summary>
<p>

- **Unsafe unlink**
	- link
	> abc

</p>
</details>

### Tcache

<details>
<summary><strong>Tcache linked list attack</strong></summary>
<p>

- **Tcache poisoning**
	- [docs](/heap/pwn_demos/tcache/tcache_poisoning/readme.md)
	> poisoning next ptr of tcache bin to get arbitrary allocate...

</p>
</details>

<details>
<summary><strong>Tcache double free</strong></summary>
<p>

- **Tcache key double**
	- [docs](/heap/pwn_demos/tcache/tcache_key_double/readme.md)
	> successful tcache double free via modify tcache chunk's key...

- **Tcache fastbin double**
	- [docs](/heap/pwn_demos/tcache/tcache_fastbin_double/readme.md)
	> successful tcache double free between tcache/fastbin...

- **Tcache size double**
	- [docs](/heap/pwn_demos/tcache/tcache_size_double/readme.md)
	> successful tcache double free between different size...

</p>
</details>

<details>
<summary><strong>Free custom tcache chunk</strong></summary>
<p>

- **Tcache fake chunk**
	- [docs](/heap/pwn_demos/tcache/tcache_fake_chunk/readme.md)
	> inserting a fake chunk with free into the tcache...

</p>
</details>

### Fastbin

<details>
<summary><strong>Fastbin linked list attack</strong></summary>
<p>

- **Fastbin poisoning**
	- [docs](/heap/pwn_demos/fastbin/fastbin_poisoning/readme.md)
	> poisoning next ptr of fastbin to get arbitrary allocate...

</p>
</details>

<details>
<summary><strong>Fastbin double free</strong></summary>
<p>

- **Fastbin double**
	- [docs](/heap/pwn_demos/fastbin/fastbin_double/readme.md)
	> successful fastbin double free...

</p>
</details>

<details>
<summary><strong>Free custom fastbin chunk</strong></summary>
<p>

- **Fastbin fake chunk**
	- link
	> abc

</p>
</details>

### Unsortedbin

<details>
<summary><strong>Overlapping chunk via unsortedbin</strong></summary>
<p>

- **Unsortedbin exact fit**
	- [docs](/heap/pwn_demos/unsortedbin/unsortedbin_exact_fit/readme.md)
	> allocate overlapping chunks via exact fit mechanism...

- **Unsortedbin last remainder**
	- [docs](/heap/pwn_demos/unsortedbin/unsortedbin_last_remainder/readme.md)
	> reallocate allocated chunks without freeing, via leveraging the last_remainder...

</p>
</details>

<details>
<summary><strong>Unsortedbin linked list attack</strong></summary>
<p>

- **Unsortedbin poisoning**
	- [docs](/heap/pwn_demos/unsortedbin/unsortedbin_poisoning/readme.md)
	> allocate chunk into stack leveraging unsortedbin linked list...

- **Unsortedbin attack (?)**
	- link
	> abc

</p>
</details>

<details>
<summary><strong>Free custom unsortedbin chunk</strong></summary>
<p>

- **Unsortedbin fake chunk**
	- link
	> abc

</p>
</details>

### Largebin

<details>
<summary><strong>Largebin linked/skip list attack</strong></summary>
<p>

- **Largebin linked poisoning**
	- [docs](/heap/pwn_demos/largebin/largebin_linked_poisoning/readme.md)
	> allocate chunk into stack leveraging large bin linked list...

- **Largebin skip poisoning**
	- [docs](/heap/pwn_demos/largebin/largebin_skip_poisoning/readme.md)
	> allocate chunk into stack leveraging large bin skip list...

- **Largebin attack**
	- link
	> abc

</p>
</details>

### Smallbin

<details>
<summary><strong>Smallbin linked list attack</strong></summary>
<p>

- **Smallbin poisoning**
	- [docs](/heap/pwn_demos/smallbin/smallbin_poisoning/readme.md)
	> allocate chunk into the stack leveraging small bin linked list...

</p>
</details>

---
## Techniques

Leverage heap's bugs/primitives to get code execution.

### Remote code execution

<details>
<summary><strong>Targetting</strong></summary>
<p>

- **libc GOT entries**
	- [docs](/heap/pwn_demos/targetting/got_libc/readme.md)
	> similar to GOT overwrite...

</p>
</details>

<details>
<summary><strong>Houses</strong></summary>
<p>

- **House of botcake**
	- [docs](/heap/pwn_demos/houses/house_of_botcake/readme.md)
	> **double free primitive**, bypass tcache dbf's key check, making overlapping chunk, return arbitrary allocation...

</p>
</details>

