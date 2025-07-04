Heap related (update later)

### Write-ups index

<details>
<summary><strong>libc 2.34</strong></summary>
<p>

- **MetaCTF 2021** --> hookless
	- [write-up](/challs/metactf/hookless/readme.md)
	> dbf in `delete` function, uaf in `display` function, uaf in `edit` function (usable once) -> custom `house of botcake`, then overwrite libc strlen got entry with one_gadget...

</p>
</details>

<details>
<summary><strong>libc 2.31</strong></summary>
<p>

- **CyberSpace CTF 2024** --> shop
	- [write-up](/challs/cyberspacectf/shop/readme.md)
	> obiviously double free but no leak function, use `stdout 0.5` trick to have a leak then perform fsop...

- **Dreamhack wargame** --> heap chall 1
	- [write-up](/challs/dreamhack/heap_chall_1/readme.md)
	> obviously double free but no leak function, the program auto add a **null byte** after input data, **modify** `stdout 0.5` trick a little to get a leak...

</p>
</details>