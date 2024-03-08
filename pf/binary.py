from typing import Union, Optional, Dict, List
from pathlib import Path
import angr
from angr.analyses import CFGFast

proj = None
class Binary:
    def __init__(self, program_path: Union[str, Path]) -> None:
        
        if type(program_path) == str:
            program_path = Path(program_path)
    
        elif isinstance(program_path, Path):
            pass
    
        else:
            raise TypeError(type(program_path))
    
        self.proj = angr.Project(program_path, load_options={
            "auto_load_libs" : False
        })
        
        self._instruction_addr_name = {}


        cfgfast: CFGFast = self.proj.analyses.CFGFast(
            normalize=True, force_complete_scan=False
        )

        self.cfgfast = cfgfast

    @property
    def cfg(self) -> CFGFast:
        return self.cfgfast

    def instruction_at(self, addr: int) :
        instruction = self.proj.factory.block(addr).disassembly
        return instruction

    @property
    def blocks_number(self) -> int:
        return len(self.cfgfast.graph.nodes)
    
    def edges_num(self)-> int:
        return self.cfgfast.graph.number_of_edges()


    def add_instruction_addr_name(self, addr: int, name: str) -> None:
        self._instruction_addr_name[addr] = name
    
    def instruction_name_at(self, addr: int) -> Optional[str]:
        return self._instruction_addr_name.get(addr)
    
    @property
    def instruction_addr_name(self) -> Dict[int, str]:
        '''
        map address to address'name(e.g. main+0x10)
        '''
        return self._instruction_addr_name
    @property
    def block_entry_addresses(self) -> List[int]:
        '''
        all basic block's entry addresses 
        '''
        return [bb.addr for bb in self.cfgfast.graph.nodes]



