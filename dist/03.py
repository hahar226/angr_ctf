import angr

p = angr.Project("03_angr_symbolic_registers")
init_state = p.factory.entry_state()
sm = p.factory.simgr(init_state)
sm.explore(find=0x80489E6,avoid=0x80489D4)
if sm.found:
    find_state = sm.found[0]
    print(find_state.posix.dumps(0))