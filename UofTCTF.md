# UofTCTF 2024 Writeup

Hello, I'm 9x14S and I participated on this CTF as a member of team 0xE0F.

## Flags

### Pwn
- basic-overflow `uoftctf{libc_is_abundant_of_gadgets}`
- baby-shellcode `uoftctf{arbitrary_machine_code_execution}`
- patched-shell `uoftctf{patched_the_wrong_function}`
- nothing-to-return `uoftctf{you_can_always_return}`

### OSINT
- Flying High `UofTCTF{BOD_Iberia_A340-300}`

### Misc
- Out of the Bucket 1 `uoftctf{allUsers_is_not_safe}`
- Out of the Bucket 2 `uoftctf{s3rv1c3_4cc0un75_c4n_83_un54f3}`

### Jail
- Baby's First Pyjail `uoftctf{you_got_out_of_jail_free}`
- Baby JS Blacklist `uoftctf{b4by_j4v4scr1p7_gr3w_up_4nd_b3c4m3_4_h4ck3r}`

### Crypto
- Repeat `uoftctf{x0r_iz_r3v3rs1bl3_w17h_kn0wn_p141n73x7}`
- Pianoman `uoftctf{AT1d2jMCVs03xxalViU9zTyiiV1INNJY}`

### Forensics 
- Secret Message 1 `uoftctf{fired_for_leaking_secrets_in_a_pdf}`
- EnableMe `uoftctf{d0cx_f1l35_c4n_run_c0de_t000}`

### Rev
- CSS Password ``

### Web
- Voice Changer `uoftctf{Y0UR Pitch IS 70O H!9H}`
- The Varsity ``
- No Code ``

### IoT 
- IoT Intro `{i_understand_the_mission}`
- Baby's First IoT Flag 1 `{FCC_ID_Recon}`
- Baby's First IoT Flag 2 `{Processor_Recon}`
- Baby's First IoT Flag 6 `{Xor!=Encryption}`

## Solves

### Pwn

#### Basic-Overflow

This challenge provides a binary called `buffer-overflow`.

Running it gives no output, only waits for user input. Like most challenges like this, they just focus on the exploitation so I immediately threw it into gdb and inputted a cyclic pattern of length 200.



