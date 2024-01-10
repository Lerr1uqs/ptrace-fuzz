from pathlib import Path
from typing import Union
from pf.binary import Binary

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
def create_child_process(args: List[str], fuzzout_fd: int, env: Dict[str, str]) -> int:

    # Fork process
    pid = os.fork()
    if pid:
        # father
        # close(errpipe_write)
        # _createParent(pid, errpipe_read)
        # os.waitpid(pid, 0)
        return pid
    else:
        # children
        try:
            print(fuzzout_fd)
            os.dup2(fuzzout_fd, 0) # 将stdin指向fuzzout_fd
            # /usr/include/linux/ptrace.h
            PTRACE_TRACEME = 0
            result = libc.ptrace(PTRACE_TRACEME, pid, 0, 0) # check_errno

            print("PTRACE_TRACEME over")
            if env is not None:
                os.execvpe(args[0], args, env)
            else:
                os.execvp(args[0], args)
    
        except Exception as err:
            raise RuntimeError(str(err))

        raise Exception("unreachable")


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
    def __init__(self, program_path: Union[str, Path]) -> None:

        if type(program_path) == str:
            program_path = Path(program_path)
    
        elif isinstance(program_path, Path):
            pass
    
        else:
            raise TypeError

        # pid = createChild([program_path], False, env=None)
        pread_fd, pwrite_fd = os.pipe()

        print(pread_fd)
        pid = create_child_process([program_path], pread_fd, env=None)

        data = b"Hello, femboy!"
        os.write(pwrite_fd, data)

        # Create the debugger and attach the process
        self._debugger = (dbg     := PtraceDebugger())
        self._process  = (process := dbg.addProcess(pid, is_attached=True))
        self._binary   = (binary  := Binary(program_path))

        graph = binary.cfg.graph
        for bb in graph.nodes:
            # binary.instruction_at(bb.addr)
            if bb.addr >= 0x500000 : # TODO: angr会将个别无法在静态定位的函数放到这个位置 这些位置是不允许被ptrace读写的
                continue

            self.binary.add_instruction_addr_name(bb.addr, bb.name)
            process.createBreakpoint(bb.addr)

        # NOTE: patch the process
        self._process.removeBreakpoint = types.MethodType(removeBreakpoint, process)

    @property
    def binary(self) -> Binary:
        return self._binary
    
    @property
    def pid(self) -> None:
        return self._process.pid
    
    def finish(self) -> None:
        self._debugger.quit()
    
    def execute(self, callback: Callable[[PtraceProcess, int], None], *args, **kvargs) -> None:
        
        if len(inspect.getfullargspec(callback)) < 2:
            raise TypeError("function signature is `def Function(process,rip) -> None`")

        print("execute")

        process = self._process

        # TODO: 在这个地方添加crash捕捉
        while True:

            process.cont()

            event: ProcessSignal = process.waitEvent()
            if event.signum != signal.SIGTRAP:
                print(f"encounter event {event}, exit")
                break

            rip = process.getreg("rip") - 1

            callback(process, rip, *args, **kvargs)
    
            process.removeBreakpoint(EmuBreakpoint(rip))
            process.setreg("rip", rip)
            process.singleStep()

            status = ctypes.c_int()
            libc.waitpid(process.pid, ctypes.byref(status), 0)
            if status.value == 0x0581:  # 等于 0x0581 表示子进程退出 TODO:
                print("Program exited")
                break

            process.createBreakpoint(rip)
