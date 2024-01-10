from pf import Ptracer
from ptrace.debugger.process import PtraceProcess
from typing import Dict
from pf import Binary
from collections import defaultdict

# 这是你需要写的函数 任何逻辑在其中完成即可
def coverage_collect(process: PtraceProcess, rip: int, coverage: Dict[int, int], binary: Binary) -> None:
    print(f"hit at {binary.instruction_name_at(rip)} where 0x{rip:x}")
    if rip in binary.block_entry_addresses:
        # hit a basic block
        coverage[rip] += 1


def main():

    p = "./samples/hello"
    p = "./samples/read_in"

    coverage = defaultdict(lambda: 0)

    ptracer = Ptracer(p)
    binary = ptracer.binary

    ptracer.execute(
        coverage_collect,
        coverage,
        binary
    )
    ptracer.finish()

    rate = len(coverage.keys()) / binary.blocks_number
    print(f"coverage rate is {rate:2f}")

if __name__ == "__main__":
    main()