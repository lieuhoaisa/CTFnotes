a
b
c

## Return oriented programming

Various ROP (or buffer overflow style) challenges/tricks/techniques.

### Stack pivot

<details>
<summary><strong>No leak functions</strong></summary>
<p>

- **Dreamhack wargame** --> pop rdi
	- [write-up](/challs/dreamhack/pop_rdi/readme.md)
	> restricted gadget, use stack pivot + add_gadget to modify saved registers values during functions internal...

- **UMDCTF 2025** --> prison realm
	- [write-up](/challs/umdctf/prison_realm/readme.md)
	> use stack pivot + add_gadget -> attack GOT to create custom rop gadget...

</p>
</details>

### GOT overwrite



