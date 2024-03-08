from pathlib import Path
from typing import Union
from pf.binary import Binary
from pf.queue import QueueEntry
from collections import defaultdict

from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.process import PtraceProcess
from ptrace.debugger.ptrace_signal import ProcessSignal
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram

from typing import Dict, Callable, List
from pf.binary import Binary
from angr.analyses import CFGFast

from elftools.elf.elffile import ELFFile
import inspect
import signal
import types
import ctypes
import os
import subprocess
import time
import selectors
# def createChild(arguments, no_stdout, env=None, close_fds=True, pass_fds=()):
#     """
#     Create a child process:
#      - arguments: list of string where (e.g. ['ls', '-la'])
#      - no_stdout: if True, use null device for stdout/stderr
#      - env: environment variables dictionary

#     Use:
#      - env={} to start with an empty environment
#      - env=None (default) to copy the environment
#     """

#     if pass_fds and not close_fds:
#         close_fds = True

#     errpipe_read, errpipe_write = pipe()
#     _set_cloexec_flag(errpipe_write)

#     # Fork process
#     pid = fork()
#     if pid:
#         # father
#         close(errpipe_write)
#         _createParent(pid, errpipe_read)
#         return pid
#     else:
#         close(errpipe_read)
#         _createChild(arguments,
#                      no_stdout,
#                      env,
#                      errpipe_write,
#                      close_fds=close_fds,
#                      pass_fds=pass_fds)









# 这是fork子进程的函数 里面把fuzzout这个fd替换为了子进程的标准输入 你只需要往fuzzout_fd这个管道里面写你的变异数据就行了
def create_child_process(args: List[str], fuzzout_fd: int,null_fd:int, env: Dict[str, str]) -> int:

    # Fork process
    pid = os.fork()
    if pid:
        # father
        # close(errpipe_write)
        # _createParent(pid, errpipe_read)
        # os.waitpid(pid, 0)
        return pid
    else:
        print(fuzzout_fd)
        os.dup2(fuzzout_fd, 0) # 将stdin指向fuzzout_fd
        os.dup2(null_fd,1)
        # /usr/include/linux/ptrace.h
        PTRACE_TRACEME = 0
        result = libc.ptrace(PTRACE_TRACEME, pid, 0, 0) # check_errno

        print("PTRACE_TRACEME over")
        if env is not None:
            os.execvpe(args[0], args, env)
        else:
            os.execvp(args[0], args)
        # children
        # @ TODO 优化fuzzer
        # try:
        #     print(fuzzout_fd)
        #     os.dup2(fuzzout_fd, 0) # 将stdin指向fuzzout_fd
        #     #os.dup2(null_fd,1)
        #     # /usr/include/linux/ptrace.h
        #     PTRACE_TRACEME = 0
        #     result = libc.ptrace(PTRACE_TRACEME, pid, 0, 0) # check_errno

        #     print("PTRACE_TRACEME over")l
        #     if env is not None:
        #         os.execvpe(args[0], args, env)
        #     else:
        #         os.execvp(args[0], args)
    
        # except Exception as err:
        #     raise RuntimeError(str(err))

        # raise Exception("unreachable")


from ctypes import CDLL
from ctypes.util import find_library

LIBC_FILENAME = find_library('c')
libc = CDLL(LIBC_FILENAME, use_errno=True)

class EmuBreakpoint:
    def __init__(self, addr) -> None:
        self.address = addr

def removeBreakpoint(self, breakpoint):
    # avoid circular call this function (this is a lib bug)
    if breakpoint.address in self.breakpoints.keys():
        del self.breakpoints[breakpoint.address] # auto remove the key

class Ptracer:
    def __init__(self, program_path: Union[str, Path],sample_queue:List[QueueEntry],null_fd:int,out_dir=None) -> None:
        #queue
        self.null_fd=null_fd
        self.out_dir=out_dir
        self.crash_dir = os.path.join(self.out_dir, "crashes")
        self.fuzz_queue=sample_queue
        self.program_path=program_path
        self.breakpoints=set()
        self.coverage=defaultdict(lambda: 0)
        self.current_queue=None
        # @TODO : timeout setting
        self.test_flag=True
        self.timeout=1
        self.selector=selectors.DefaultSelector()

        #break and init 
        if type(program_path) == str:
            program_path = Path(program_path)
    
        elif isinstance(program_path, Path):
            pass
    
        else:
            raise TypeError

        # pid = createChild([program_path], False, env=None)
        self.pread_fd, self.pwrite_fd = os.pipe()

        #print(pread_fd)
        self.pid = create_child_process([program_path], self.pread_fd,null_fd, env=None)

        #test_data = b"4\naaaa\n"
        #test_data=b"2\n1\n5\n"
        # 4\n%5$n\n -> fmt fault
        # 4\naaaa\n  
        self.current_queue=self.fuzz_queue.pop()
        os.write(self.pwrite_fd, self.current_queue.read_file())

        # Create the debugger and attach the process
        self._debugger = (dbg     := PtraceDebugger())
        self._process  = (process := dbg.addProcess(self.pid, is_attached=True))
        self._binary   = (binary  := Binary(program_path))


        graph = binary.cfg.graph
        for bb in graph.nodes:
            # binary.instruction_at(bb.addr)
            # TODO: 如果编译的时候没有添加pie选项，那么creatbp就会i/o error  未知
            if bb.addr >= 0x500000 : # TODO: angr会将个别无法在静态定位的函数放到这个位置 这些位置是不允许被ptrace读写的
                continue
            
            self.binary.add_instruction_addr_name(bb.addr, bb.name)
            #print(f"break at {bb.name} where {hex(bb.addr)}")
            process.createBreakpoint(bb.addr)
            self.breakpoints.add(bb.addr)
            

        # NOTE: patch the process
        self._process.removeBreakpoint = types.MethodType(removeBreakpoint, process)

    def coverage_collect(self,rip,prev_rip) -> None:
        #print(f"hit at {self.binary.instruction_name_at(rip)} where 0x{rip:x}")
        if rip in self.binary.block_entry_addresses:
            # hit a basic block
            self.coverage[rip^prev_rip] += 1
            #print("test ++")
        else:
            1#maybe crash 


    @property
    def binary(self) -> Binary:
        return self._binary
    
    # @property
    # def pid(self) -> None:
    #     return self._process.pid
    
    def finish(self) -> None:
        self._debugger.quit()

    def showcoverage(self) -> None:
        rate = len(self.coverage.keys()) / self.binary.edges_num()
        print(f"coverage rate is {rate:2f}")

    def handle_timeout(self, signum, frame):
        # TODO 处理超时
        print("***test timeout***")
        self.showcoverage()
        #raise TimeoutError("Execution timed out")
        # if self.test_flag==True:
        #     self.test_flag=False
        self.restart()

    def restart(self):
        # TODO kill程序 重新execute pid
        self._process.kill(signal.SIGTERM)
        #os.kill(self.pid)
        pid = create_child_process([self.program_path], self.pread_fd,self.null_fd, env=None)
        new_process  = self._debugger.addProcess(pid, is_attached=True)
        for addr in self.breakpoints:
            new_process.createBreakpoint(addr)
            #print(f"break where {hex(addr)}")
        self._process=new_process
        self._process.removeBreakpoint = types.MethodType(removeBreakpoint, self._process)
        #test_data = b"1\nasda\n"
        # 4\n%5$n\n -> fmt fault
        # 4\naaaa\n  
        self.current_queue=self.fuzz_queue.pop()
        print("now input:"+self.current_queue.fname)
        print(self.current_queue.read_file())
        os.write(self.pwrite_fd, self.current_queue.read_file())
        self.execute()

    def crash_handle(self) ->None:
        filename = os.path.join(self.crash_dir, self.current_queue.fname[3:])
        with open(filename, "wb") as f:
            f.write(self.current_queue.read_file())
        # crash 变异 
    
    #def execute(self, callback: Callable[[PtraceProcess, int], None], *args, **kvargs) -> None:
    def execute(self) -> None:
        # if len(inspect.getfullargspec(callback)) < 2:
        #     raise TypeError("function signature is `def Function(process,rip) -> None`")

        print("execute")
        process = self._process
        signal.signal(signal.SIGALRM, self.handle_timeout)
        prev_rip=0xaaaaaa
        # try:
        while True:
            signal.alarm(self.timeout)
            process.cont()
            #print("waiting...")
            event: ProcessSignal = process.waitEvent()
            if event.signum != signal.SIGTRAP:
                print(f"encounter event {event.signum} {event}")
                if event.signum is None:  # 正常退出
                    print("[*] Program exited normally")
                    self.showcoverage()
                elif event.signum == signal.SIGTERM:
                    #self._process.kill(signal.SIGTERM)
                    process.detach()
                else:
                    print("[*] ***** get crash here ****")
                    print(self.current_queue.fname)
                    self.crash_handle()
                    self.showcoverage()
                    self.restart()
                    # TODO: 在这个地方添加crash捕捉
                break
            
            
            rip = process.getreg("rip") - 1
            self.coverage_collect(rip,prev_rip)
            prev_rip=rip>>1

            process.removeBreakpoint(EmuBreakpoint(rip))

            process.setreg("rip", rip)
            process.singleStep()


            # print("===========")

            # wait for child finish
            status = ctypes.c_int()
            libc.waitpid(process.pid, ctypes.byref(status), 0)
            # print(f"Waitpid status: {hex(status.value)}")

            process.createBreakpoint(rip)
        # except TimeoutError:
        #     print("test Execution timed out")
        # finally:
        #     signal.alarm(0)