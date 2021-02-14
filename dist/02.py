import angr


p = angr.Project("02_angr_find_condition")
init_state = p.factory.entry_state()
sm = p.factory.simgr(init_state)

def is_good(state):
    return b"Good" in state.posix.dumps(1)

def is_bad(state):
    return b"Try" in state.posix.dumps(1)

sm.explore(find=is_good,avoid=is_bad)

if sm.found:
    found_state = sm.found[0]
    print(found_state.posix.dumps(0))