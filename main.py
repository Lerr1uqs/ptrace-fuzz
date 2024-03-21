from pf import Ptracer
from ptrace.debugger.process import PtraceProcess
from typing import Dict
from pf import Binary
from pf import QueueEntry
from collections import defaultdict
import sys
import argparse
import os

in_dir = ""
out_dir = ""



USAGE_STRING = (
    "\nptrace_fuzz [ options ] -- /path/to/target_app [ ... ]\n\n"
    "Required parameters:\n\n"
    "-i dir        - input directory with the starting corpus\n"
    "-o dir        - output directory for minimized files\n"
    "Execution control settings:\n\n"
    "  -f file       - input file read by the tested program (stdin)\n"
    "  -t msec       - timeout for each run (%u ms)\n"
    "  -m megs       - memory limit for child process (%u MB)\n"
    "Other stuff:\n\n"
    "  -V            - show version number and exit\n\n"
    "For additional tips, please consult %s/README.\n\n"
)


def show_usages():
    print("\nptrace_fuzz [ options ] -- /path/to/target_app [ ... ]\n\n"

       "Required parameters:\n\n"

        "-i dir        - input directory with the starting corpus\n"
        "-o dir        - output directory for minimized files\n"

       "Execution control settings:\n\n"

       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"

       "Other stuff:\n\n"

       "  -V            - show version number and exit\n\n"

       "For additional tips, please consult %s/README.\n\n",)

    # 打印传递给脚本的参数
    if len(sys.argv) > 1:
        print("Arguments:")
        for arg in sys.argv[1:]:
            print(arg)
    else:
        print("No arguments provided.")


def parse_args():
    global in_dir,out_dir
    out_dir="out"

    parser = argparse.ArgumentParser(description="")

    # 添加参数
    parser.add_argument("-i", dest="input_dir", help="Input directory with the starting corpus", required=True)
    parser.add_argument("-o", dest="output_dir", help="Output directory for minimized files", required=True)
    parser.add_argument("-f", dest="input_file", help="Input file read by the tested program (stdin)")
    parser.add_argument("-t", dest="timeout", type=int, help="Timeout for each run (in milliseconds)")
    parser.add_argument("-m", dest="memory_limit", type=int, help="Memory limit for child process (in megabytes)")
    parser.add_argument("-V", dest="version", action="store_true", help="Show version number and exit")
    # 解析命令行参数
    args = parser.parse_args()

    # 使用参数
    in_dir = args.input_dir
    #out_dir = args.output_dir

def init_dirs():
    if not os.path.exists(in_dir):
        print(f"Error: The directory '{in_dir}' does not exist.")
        return
    if not any(os.scandir(in_dir)):
        print(f"Error: The directory '{in_dir}' is empty.")
        return
    
    # try:
    #     os.makedirs(out_dir)
    #     os.chmod(out_dir,0o700)
    #     print(f"Directory '{out_dir}' created successfully.")
    # except FileExistsError:
    #     print(f"Directory '{out_dir}' already exists.")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        os.chmod(out_dir, 0o700)
        print(f"Directory '{out_dir}' created successfully.")


    state_dir = os.path.join(out_dir, "queue", ".state")
    os.makedirs(state_dir, mode=0o700)

    # Directory for flagging queue entries that went through deterministic fuzzing in the past.
    deterministic_done_dir = os.path.join(state_dir, "deterministic_done")
    os.makedirs(deterministic_done_dir, mode=0o700)

    # Directory with the auto-selected dictionary entries.
    auto_extras_dir = os.path.join(state_dir, "auto_extras")
    os.makedirs(auto_extras_dir, mode=0o700)

    # The set of paths currently deemed redundant.
    redundant_edges_dir = os.path.join(state_dir, "redundant_edges")
    os.makedirs(redundant_edges_dir, mode=0o700)

    # The set of paths showing variable behavior.
    variable_behavior_dir = os.path.join(state_dir, "variable_behavior")
    os.makedirs(variable_behavior_dir, mode=0o700)

    crashes_dir = os.path.join(out_dir, "crashes")
    os.makedirs(crashes_dir, mode=0o700)

    hangs_dir = os.path.join(out_dir, "hangs")
    os.makedirs(hangs_dir, mode=0o700)

def check_crash_handling():
    core_pattern_path = "/proc/sys/kernel/core_pattern"

    try:
        with open(core_pattern_path, 'rb') as fd:
            fchar = fd.read(1)
            if fchar == b'|':
                print("\n[-] Hmm, your system is configured to send core dump notifications to an\n"
                      "    external utility. This will cause issues: there will be an extended delay\n"
                      "    between stumbling upon a crash and having this information relayed to the\n"
                      "    fuzzer via the standard waitpid() API.\n\n"
                      "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
                      "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"
                      "    echo core >/proc/sys/kernel/core_pattern\n")
                exit(1);
    except FileNotFoundError:
        pass  # Handle the case where the file is not found (not on Linux or similar)


# # 这是你需要写的函数 任何逻辑在其中完成即可
# def coverage_collect(process: PtraceProcess, rip: int, coverage: Dict[int, int], binary: Binary) -> None:
#     print(f"hit at {binary.instruction_name_at(rip)} where 0x{rip:x}")
#     if rip in binary.block_entry_addresses:
#         # hit a basic block
#         coverage[rip] += 1
#     else:
#         1#maybe crash 
    
def init_queue():
    # @TODO :read from in_dir

    global sample_queue
    # test_input1=QueueEntry()
    # test_input1.set_file("in/test1")
    # test_input2=QueueEntry()
    # test_input2.set_file("in/test2")
    # test_input3=QueueEntry()
    # test_input3.set_file("in/test3")
    # sample_queue.append()    
    file_list = os.listdir(in_dir)
    for filename in file_list:
        file_path = os.path.join(in_dir, filename)
        queue_entry = QueueEntry()
        queue_entry.set_file(file_path)
        sample_queue.append(queue_entry)



sample_queue=[]
null_fd=None
    
def main():
    global null_fd
    try:
        null_fd=os.open("/dev/null", os.O_WRONLY)
    except Exception as e:
        print(f"Error opening /dev/null: {e}")

    parse_args()
    init_queue()
    #init_dirs()

    check_crash_handling();

    p = "./samples/test"

    #p = "./samples/read_in"

    coverage = defaultdict(lambda: 0)

    ptracer = Ptracer(p,sample_queue,null_fd,out_dir)
    binary = ptracer.binary

    # ptracer.execute(
    #     coverage_collect,
    #     coverage,
    #     binary
    # )
    #ptracer.show_states()
    ptracer.start_fuzz()
    ptracer.finish()

    


if __name__ == "__main__":
    main()



