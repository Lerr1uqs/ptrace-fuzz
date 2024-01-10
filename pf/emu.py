# from unicorn import *
# from unicorn.x86_const import *
# from pathlib import Path

# class Emulator:
#     def __init__(self, prog_path: Path) -> None:

#         BASE = 0x400000
#         STACK_ADDR = 0x0
#         STACK_SIZE = 1024 * 1024

#         mu = Uc (UC_ARCH_X86, UC_MODE_32)

#         mu.mem_map(BASE, 1024 * 1024)
#         mu.mem_map(STACK_ADDR, STACK_SIZE)


#         mu.mem_write(BASE, shellcode)
#         mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE // 2)

#         def syscall_num_to_name(num):
#             syscalls = {
#                 1 : "sys_exit", 
#                 15: "sys_chmod"
#             }
#             return syscalls[num]

#         # ref: https://defuse.ca/online-x86-assembler.htm#disassembly
#         int_0x80 = b"\xCD\x80"
#         def hook_code(mu : Uc, addr, size, user_data):
#             # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(addr, size))  
            
#             inst : bytearray = mu.mem_read(addr ,size)
            
#             if inst == int_0x80:
#                 eax = mu.reg_read(UC_X86_REG_EAX)
#                 ebx = mu.reg_read(UC_X86_REG_EBX)
#                 ecx = mu.reg_read(UC_X86_REG_ECX)

#                 sysc_name = syscall_num_to_name(eax)

#                 if sysc_name == "sys_chmod" :
#                     # int chmod(const char *pathname, mode_t mode);
#                     path = mu.mem_read(ebx, 0x20).split(b'\x00')[0]
#                     print(f"[+] syscall {sysc_name} ({path.decode()}, {oct(ecx)})")

#                 if sysc_name == "sys_exit":
#                     print(f"[+] exit({ebx})")
#                     sys.exit()

#                 # all call instruction must calibrate rip
#                 mu.reg_write(UC_X86_REG_EIP, addr + size)
            

#         mu.hook_add(UC_HOOK_CODE, hook_code)
#         mu.emu_start(BASE, BASE + len(shellcode))
#             pass