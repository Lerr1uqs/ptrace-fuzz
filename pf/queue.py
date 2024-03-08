import os
class QueueEntry:
    def __init__(self) -> None:
        self.fname = None  # 字符串属性，默认为 None
        self.len = 0 # 整数属性，默认为 0
        self.cal_failed = False     # 布尔属性，默认为 False
        self.trim_done = False
        self.was_fuzzed = False
        self.passed_det = False
        self.has_new_cov = False
        self.var_behavior = False
        self.favored = False
        self.fs_redundant = False

        self.bitmap_size = 0  # 整数属性，默认为 0
        self.exec_cksum = 0  # 整数属性，默认为 0

        self.exec_us = 0  # 整数属性，默认为 0
        self.handicap = 0  # 整数属性，默认为 0
        self.depth = 0  # 整数属性，默认为 0

        self.trace_mini = None  # 字符串属性，默认为 None
        self.tc_ref = 0  # 整数属性，默认为 0

        self.next = None  # 下一个元素，默认为 None
        self.next_100 = None  # 100个元素之后的元素，默认为 None


    def len(self) -> int:
        return self.len
    
    def set_file(self,fname)->None:
        self.fname=fname
        self.len=os.path.getsize(fname)
 
    def read_file(self):
        # if self.fname is None:
        #     raise ValueError("File path is not set")
        with open(self.fname, 'rb') as file:
            # 在文件上下文管理器中读取文件内容
            content = file.read()
            # 返回文件内容
            return content