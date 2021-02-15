import angr
import claripy

p = angr.Project("03_angr_symbolic_registers")
start_address = 0x08048980
init_state = p.factory.blank_state(addr=start_address)
pass1 = claripy.BVS("pass1",32)
pass2 = claripy.BVS("pass2",32)
pass3 = claripy.BVS("pass3",32)
init_state.regs.eax = pass1
init_state.regs.ebx = pass2
init_state.regs.edx = pass3
sm = p.factory.simgr(init_state)
sm.explore(find=0x80489E6,avoid=0x80489D4)
if sm.found:
    find_state = sm.found[0]
    #scanf是%x
    print("{:x} {:x} {:x}".format(find_state.solver.eval(pass1),find_state.solver.eval(pass2),find_state.solver.eval(pass3)))
