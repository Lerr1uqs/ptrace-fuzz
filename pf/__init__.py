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
from datetime import datetime
from elftools.elf.elffile import ELFFile
from datetime import datetime
import inspect
import signal
import types
import ctypes
import os
import subprocess
import time
import selectors
import threading
import pytermgui as ptg

def color_string(text, color):
    colors = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'grey': "\033[90m",
        'reset': '\033[0m'
    }
    color_code = colors.get(color.lower(), '')
    return color_code + text + colors['reset']

def flip_bit(ar, b) ->bytes:
    arf = bytearray(ar)
    bf = b
    arf[bf >> 3] ^= (128 >> (bf & 7))
    return bytes(arf)
def write_to_testcase(out_buf)->None:
    try:
        os.unlink(CUR_TEST)
    except FileNotFoundError:
        pass
    with open(CUR_TEST, "wb") as f:
        f.write(out_buf)

def format_elapsed_time(seconds):
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02}:{:02}:{:02}".format(int(hours), int(minutes), int(seconds))


CUR_TEST = "./out/queue/cur_test"

FAULT_CRASH=0x400
FAULT_TIMEOUT=0x401
FAULT_HANGS=0x402
NORMAL_EXIT=0x403

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
        #print(fuzzout_fd)
        os.dup2(fuzzout_fd, 0) # 将stdin指向fuzzout_fd
        os.dup2(null_fd,1)
        # /usr/include/linux/ptrace.h
        PTRACE_TRACEME = 0
        result = libc.ptrace(PTRACE_TRACEME, pid, 0, 0) # check_errno

        #print("PTRACE_TRACEME over")
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
        self.fuzz_start_time=time.time()
        self.null_fd=null_fd
        self.out_dir=out_dir
        self.crash_dir = os.path.join(self.out_dir, "crashes")
        self.queue_dir = os.path.join(self.out_dir, "queue")
        self.fuzz_queue=sample_queue
        self.program_path=program_path
        self.breakpoints=set()
        self.coverage=defaultdict(lambda: 0)
        self.trace_coverage = defaultdict(lambda: 0) 
        self.current_queue=None
        # result
        self.crashes=0
        self.last_save_crash=None
        self.last_save_hang=None
        self.total_tmouts=0
        self.queue_cycle=0
        self.test_num=0
        self.cycles_done=0
        self.total_coverage_result=0
        self.trace_coverage_result=0

        # @TODO : timeout setting
        self.test_flag=True
        self.wait_timeout=1
        self.execute_timeout=2
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

        # print(pread_fd)
        # self.pid = create_child_process([program_path], self.pread_fd,null_fd, env=None)

        #test_data = b"4\naaaa\n"
        #test_data=b"2\n1\n5\n"
        # 4\n%5$n\n -> fmt fault
        # 4\naaaa\n  
        # self.current_queue=self.fuzz_queue.pop()
        # os.write(self.pwrite_fd, self.current_queue.read_file())

        # Create the debugger and attach the process
        self._debugger = (dbg     := PtraceDebugger())
        self._process = None
        # self._process  = (process := dbg.addProcess(self.pid, is_attached=True))
        self._binary   = (binary  := Binary(program_path))


        graph = binary.cfg.graph
        for bb in graph.nodes:
            # binary.instruction_at(bb.addr)
            # TODO: 如果编译的时候没有添加pie选项，那么creatbp就会i/o error  未知
            if bb.addr >= 0x500000 : # TODO: angr会将个别无法在静态定位的函数放到这个位置 这些位置是不允许被ptrace读写的
                continue
            
            self.binary.add_instruction_addr_name(bb.addr, bb.name)
            #print(f"break at {bb.name} where {hex(bb.addr)}")
            #process.createBreakpoint(bb.addr)
            self.breakpoints.add(bb.addr)
            

        # # NOTE: patch the process
        # self._process.removeBreakpoint = types.MethodType(removeBreakpoint, process)
        # show thread
        show_states_thread = threading.Thread(target=self.show_states)
        show_states_thread.daemon = True  # 设置为守护线程，确保主线程退出时该线程也会退出
        show_states_thread.start()  # 启动线程




    def coverage_collect(self,rip,prev_rip) -> None:
        #print(f"hit at {self.binary.instruction_name_at(rip)} where 0x{rip:x}")
        if rip in self.binary.block_entry_addresses:
            # hit a basic block
            self.trace_coverage[rip^prev_rip] += 1
            self.trace_coverage_result= len(self.trace_coverage.keys()) / self.binary.edges_num()
            #print("test ++")
        else:
            1#maybe crash 


    @property
    def binary(self) -> Binary:
        return self._binary
    
    # @property
    # def pid(self) -> None:
    #     return self._process.pid
    
    def has_new_edge(self) -> bool:
        """
        Check if there are any new edges covered in the trace_coverage.

        Returns:
            bool: True if there are new edges covered, False otherwise.
        """
        trace_edges = set(self.trace_coverage.keys())
        coverage_edges = set(self.coverage.keys())

        return trace_edges - coverage_edges != set()


    def update_coverage(self)->None:
        #TODO
        for edge,count in self.trace_coverage.items():
            if edge in self.coverage:
                if(self.coverage[edge]<count):
                    self.coverage[edge]=count
            else:
                self.coverage[edge]=count
        self.total_coverage_result = len(self.coverage.keys()) / self.binary.edges_num()
        
    def start_fuzz(self) ->None:
        

        #test_data = b"4\naaaa\n"
        #test_data=b"2\n1\n5\n"
        # 4\n%5$n\n -> fmt fault
        # 4\naaaa\n  

        #self.common_fuzz_stuff(b"tetateata")


        #fuzz 主循环

        while True:

            while(self.fuzz_queue):
                self.fuzz_one()
            self.queue_cycle+=1

    def abandon_entry(self):
        return 0


    def fuzz_one(self) -> int :
        self.trace_coverage.clear()
        if self._process is not None:
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
        if self.current_queue.was_fuzzed==False:
            #print("now input:"+self.current_queue.fname)
            #print(self.current_queue.read_file())
            out_buf=self.current_queue.read_file()
            os.write(self.pwrite_fd, out_buf)
            result= self.execute()
            self.save_if_interesting(out_buf,result)
            self.update_coverage()
            return 0

        #return 0
        #TODO 
        # @1_1
        out_buf=self.current_queue.read_file()
        len=self.current_queue.len
        stage_max=len
        for stage_cur in range(stage_max):
            stage_cur_byte = stage_cur >> 3
            #print(b"before:"+out_buf)
            out_buf=flip_bit(out_buf, stage_cur)
            #print(b"out:"+out_buf)
            if (self.common_fuzz_stuff(out_buf)):
                self.abandon_entry()
            out_buf=flip_bit(out_buf, stage_cur)
        # @2_1
        stage_max = (len << 3) - 1
        for stage_cur in range(stage_max):
            out_buf=flip_bit(out_buf, stage_cur)
            flip_bit(out_buf, stage_cur + 1)
            if (self.common_fuzz_stuff(out_buf)):
                self.abandon_entry()
            out_buf=flip_bit(out_buf, stage_cur)
            flip_bit(out_buf, stage_cur + 1)
        # @4_1
        stage_max = (len << 3) - 3
        for stage_cur in range(stage_max):
            out_buf=flip_bit(out_buf, stage_cur)
            flip_bit(out_buf, stage_cur + 1)
            flip_bit(out_buf, stage_cur + 2)
            flip_bit(out_buf, stage_cur + 3)
            if (self.common_fuzz_stuff(out_buf)):
                self.abandon_entry()
            out_buf=flip_bit(out_buf, stage_cur)
            flip_bit(out_buf, stage_cur + 1)
            flip_bit(out_buf, stage_cur + 2)
            flip_bit(out_buf, stage_cur + 3)
        # @8_8
        stage_max=len
        out_buf = bytearray(out_buf)
        out_buf[stage_cur] ^= 0xFF
        for stage_cur in range(stage_max):
            stage_cur_byte = stage_cur

            out_buf[stage_cur] ^= 0xFF
            if (self.common_fuzz_stuff(out_buf)):
                self.abandon_entry()
            out_buf[stage_cur] ^= 0xFF
        # @16_8
        stage_cur = 0
        stage_max = len - 1
        for i in range(len - 1):
            stage_cur_byte = i
            # Assuming out_buf is a bytes-like object
            out_buf = bytearray(out_buf)
            u16_value = int.from_bytes(out_buf[i:i+2], byteorder='little')
            u16_value ^= 0xFFFF
            out_buf[i:i+2] = u16_value.to_bytes(2, byteorder='little')

            if self.common_fuzz_stuff(out_buf):
                self.abandon_entry()
            stage_cur += 1

            # Revert the change
            u16_value ^= 0xFFFF
            out_buf[i:i+2] = u16_value.to_bytes(2, byteorder='little')
            #self.update_coverage()



    def test_queue(self,queue:QueueEntry)->int:
        self.trace_coverage.clear()
        if self._process is not None:
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
        #self.current_queue=self.fuzz_queue.pop()
        self.current_queue=queue
        #print("now input:"+self.current_queue.fname)
        #print(self.current_queue.read_file())
        os.write(self.pwrite_fd, self.current_queue.read_file())
        result= self.execute()
        #TODO 
        self.update_coverage()
        return result


    def finish(self) -> None:
        self._debugger.quit()


    # @TODO 变异函数 
    #跟进去trim_case函数，如下所示。思路是根据一定的策略删除种子中的部分数据，
    #用删除后的种子作为输入运行目标程序，如果路径覆盖率的hash值与删除前的hash值一致，说明数据被删除不影响代码覆盖率，可以删除。
    def trim_case(self) ->None:
        1
    def calculate_score(self)->None:
        1
    
    def save_if_interesting(self,out_buf,fault)->int:
        # TODO
        if self.has_new_edge():
            current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = os.path.join(self.queue_dir,f"id:{current_time}")
            with open(filename, "wb") as f:
                f.write(out_buf)
            new_queue=QueueEntry()
            new_queue.set_file(filename)
            new_queue.was_fuzzed=True
            self.fuzz_queue.insert(0,new_queue)
            if fault==FAULT_CRASH:
                self.crash_handle()
            elif fault==FAULT_TIMEOUT:
                return 0
            elif fault==FAULT_HANGS:    
                self.total_tmouts+=1
                return 1
            return 0
        else:
            return 1

    def common_fuzz_stuff(self,out_buf)->int:
        write_to_testcase(out_buf)
        test_queue=QueueEntry()
        test_queue.set_file(CUR_TEST)
        # print(test_queue.len)
        # print(test_queue.read_file())
        fault=self.test_queue(test_queue)
        #if fault==FAULT_TIMEOUT:
        result=self.save_if_interesting(out_buf,fault)
        self.update_coverage()
        return result

    # def bitflip(self,queue:QueueEntry):
    #     #1——1
    #     out_buf=queue.read_file()
    #     stage_max=queue.len<<3
    #     for stage_cur in range(stage_max):
    #         stage_cur_byte = stage_cur >> 3
    #         out_buf=flip_bit(out_buf, stage_cur)
    #         if (self.common_fuzz_stuff(out_buf)):
    #             1
    #         out_buf=flip_bit(out_buf, stage_cur)

    def showcoverage(self) -> None:
        rate = len(self.coverage.keys()) / self.binary.edges_num()
        #print(f"coverage rate is {rate:2f}")

    def exit_program(self,manager:ptg.WindowManager):
        manager.stop()

    # def get_num(self):
    #     self.test_num+=1
    #     return self.test_num
        
    def macro_time(self,fmt: str) -> str:
        run_time=time.time()-self.fuzz_start_time
        return format_elapsed_time(run_time)

    def get_crashnum(self,fmt:str)->str:
        return str(self.crashes)

    def get_last_crash(self,fmt:str)->str:
        if self.last_save_crash is None:
            return "None"
        return self.last_save_crash.strftime("%Y-%m-%d %H:%M:%S")

    def get_trace_coverage(self,fmt:str)->str:
        coverage_str = "{:.2%}".format(self.trace_coverage_result)
        return coverage_str

    def get_total_coverage(self,fmt:str)->str:
        coverage_str = "{:.2%}".format(self.total_coverage_result)
        return coverage_str



    def show_states(self) -> None:
        #print("here")
        #ptg.tim.define("!time",self.get_num)
        ptg.tim.define("!time", self.macro_time)
        ptg.tim.define("!crash_num", self.get_crashnum)
        ptg.tim.define("!get_last_crash", self.get_last_crash)
        ptg.tim.define("!get_trace_coverage", self.get_trace_coverage)
        ptg.tim.define("!get_total_coverage", self.get_total_coverage)


        CONFIG = """
        config:
            Label:
                styles:
                    value: green
                parent_align: 0

            Window:
                styles:
                    border: '1'
                    corner: '3'


        """

        container1 = ptg.Window(
            ptg.Label("         run time :  [!time 83]%c"),
            ptg.Label("    last new find :  xx"),
            ptg.Label(" last saved crash :  [!get_last_crash 83]%c"),
            ptg.Label("  last saved hang :  xx"),
            width=25,
            height=2,
        )
        container1.set_title('[blue]process timing')

    # 创建第二个Container
        container2 = ptg.Window(
            ptg.Label("  cycles done :  xx"),
            ptg.Label(" corpus count :  xx"),
            ptg.Label(" save crashes :  [!crash_num 83]%c"),
            ptg.Label("   save hangs :  xx"),
            width=25,
            height=2,

        )
        container2.set_title('[blue]overall results')

        container3 = ptg.Window(
            ptg.Label(" now processing : 0.18 (0.0%)"),
            ptg.Label(" runs timed out : 0 (0.00%)"),
            width=25,
            height=1,
        )
        container3.set_title('[blue]cycle progress')

        container4 = ptg.Window(
            ptg.Label("    map density : [!get_trace_coverage 83]%c"),
            ptg.Label(" count coverage : [!get_total_coverage 83]%c"),
            width=25,
            height=1,
        )
        container4.set_title('[blue]map coverage')

        container5 = ptg.Window(
            ptg.Label("  now trying : havoc"),
            ptg.Label(" stage execs : 141/918 (15.36%)"),
            ptg.Label(" total execs : 15.0k"),
            ptg.Label("  exec speed : 2086/sec"),
            width=25,
            height=2,
        )
        container5.set_title('[blue]stage progress')

        container6 = ptg.Window(
            ptg.Label("    bit flips : disabled (default, enable with -D)"),
            ptg.Label("   byte flips : disabled (default, enable with -D)"),
            ptg.Label("  arithmetics : disabled (default, enable with -D)"),
            ptg.Label("   known ints : disabled (default, enable with -D)"),
            ptg.Label("   dictionary : n/a"),
            ptg.Label(" havoc/splice : 1/14.9k, 0/0"),
            ptg.Label("     trim/eff : n/a, disabled"),
            width=25,
            height=2,
        )
        container6.set_title('[blue]fuzzing strategy yields')

        # 创建右中间容器
        container7 = ptg.Window(
            ptg.Label(" favored items : 1 (100.00%)"),
            ptg.Label("  new edges on : 1 (100.00%)"),
            ptg.Label(" total crashes : 21 (1 saved)"),
            ptg.Label("  total tmouts : 0 (0 saved)"),
            width=25,
            height=2,
        )
        container7.set_title('[blue]findings in depth')

        # 创建底部容器
        container8 = ptg.Window(
            ptg.Label("    levels : 1"),
            ptg.Label("   pending : 0"),
            ptg.Label("  pend fav : 0"),
            ptg.Label(" own finds : 0"),
            ptg.Label("  imported : 0"),
            ptg.Label("  stability : 100.00%"),
            width=25,
            height=2,
        )
        container8.set_title('[blue]item geometry')
        splitter1 = ptg.Splitter(container1,container2)
        splitter1.visible=False
        splitter2 = ptg.Splitter(container3, container4)
        splitter2.visible = False

        splitter3 = ptg.Splitter(container5, container7)
        splitter3.visible = False

        splitter4 = ptg.Splitter(container6, container8)
        splitter4.visible = False


        with ptg.YamlLoader() as loader:
            loader.load(CONFIG)

        with ptg.WindowManager() as manager:
            window = (
                ptg.Window(
                    splitter1,
                    splitter2,
                    splitter3,
                    splitter4,

                    ["Exit", lambda *_: self.exit_program(manager)],
                    width=100,
                    box="DOUBLE",
                )
                .set_title("[210 bold]AFL Output")
                .center()
            )
            manager.layout.add_slot("Body")
            manager.add(window)
            #print("start run")
            #manager.run()
            #manager.run()


    def handle_timeout(self, signum, frame):
        # TODO 处理超时
        #print("***test timeout***")
        self.showcoverage()
        self._process.kill(signal.SIGALRM)
        return

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
        #print("now input:"+self.current_queue.fname)
        #print(self.current_queue.read_file())
        os.write(self.pwrite_fd, self.current_queue.read_file())
        self.execute()

    def crash_handle(self) ->None:
        self.crashes+=1
        self.last_save_crash=datetime.now()
        filename = os.path.join(self.crash_dir, os.path.basename(self.current_queue.fname))
        with open(filename, "wb") as f:
            f.write(self.current_queue.read_file())
            #f.close()

    
    #def execute(self, callback: Callable[[PtraceProcess, int], None], *args, **kvargs) -> None:
    def execute(self) -> int:
        # if len(inspect.getfullargspec(callback)) < 2:
        #     raise TypeError("function signature is `def Function(process,rip) -> None`")
        self.queue_cycle+=1


        process = self._process
        signal.signal(signal.SIGALRM, self.handle_timeout)
        start_time=time.time()
        
        prev_rip=0xaaaaaa
        # try:
        while True:
            signal.alarm(self.wait_timeout)
            process.cont()  
            execution_time =time.time()-start_time
            if execution_time > self.execute_timeout:
                #print('hangs')
                return FAULT_HANGS
            #print("here")
            event: ProcessSignal = process.waitEvent()
            if event.signum != signal.SIGTRAP:
                #print(f"encounter event {event.signum} {event}")
                if event.signum is None:  # 正常退出
                    #print("[*] Program exited normally")
                    #self.update_coverage()
                    self.showcoverage()
                    return NORMAL_EXIT
                elif event.signum == signal.SIGTERM:
                    #self._process.kill(signal.SIGTERM)
                    #print("Get timeout")
                    process.detach()
                    #self.update_coverage()
                    return 0
                elif event.signum == signal.SIGALRM:
                    #print("get timeout")
                    return FAULT_TIMEOUT
                else:
                    #print("[*] ***** get crash here ****")
                    #print(self.current_queue.fname)
                    #self.update_coverage()
                    #self.crash_handle()
                    self.showcoverage()
                    #self.restart()
                    return FAULT_CRASH
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