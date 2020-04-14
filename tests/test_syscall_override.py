import nose
import angr

import logging
l = logging.getLogger("angr.tests")

import os
# test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')
# sample_path = "/home/wanghuozhu/ws/share/gitlabshare/linuxPintool-master/source/tools/ManualExamples/temphz/asmTest"
sample_path = "/home/wanghuozhu/ws/other/angr-doc/examples/fauxware/fauxware"

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006F1 ],""" angr example:0x4006ed    4007D4 """
    'ppc': [ 0x1000060C ],
    'armel': [ 0x85F0 ],
    'mips': [ 0x4009FC ]
}

avoid_addrs = {
    'i386': [ 0x080485DD,0x08048564 ],
    'x86_64': [ 0x400701 ], """" 0x4006aa,0x4006fd """
    'ppc': [ 0x10000644,0x1000059C ],
    'armel': [ 0x86F8,0x857C ],
    'mips': [ 0x400A10,0x400774 ]
}

corrupt_addrs = { # not used
    'i386': [ 0x80486B6, b'bO\xcc', lambda s: s.memory.store(s.regs.esp, s.regs.eax) ],
    'x86_64': [ 0x400742, b'\xd4&\xb0[\x41', lambda s: s.registers.store('rdx', 8) ],
    'ppc': [ 0x100006B8, b'\x05\xad\xc2\xea', lambda s: s.registers.store('r5', 8) ],
    'armel': [ 0x8678, b'\xbdM\xec3', lambda s: s.registers.store('r2', 8) ],
    'mips': [ 0x400918, b'[\xf8\x96@'[::-1], lambda s: s.registers.store('a2', 8) ]
}

def run_fauxware_override(arch):
    # p = angr.Project(os.path.join(test_location, arch, "fauxware"), use_sim_procedures=False)
    p = angr.Project(sample_path, use_sim_procedures=False) # auto_load_libs=False
    s = p.factory.full_init_state()

    def overwrite_str(state):
        state.posix.get_fd(1).write_data(b"HAHA\0")

    queued_syscall_returns = [ ]
    queued_syscall_returns.append(None) # let the mmap run
    queued_syscall_returns.append(overwrite_str) # prompt for username
    queued_syscall_returns.append(0) # username read
    queued_syscall_returns.append(0) # newline read
    #queued_syscall_returns.append(0) # prompt for password -- why isn't this called?
    queued_syscall_returns.append("None") # password input #SOSNEAKY
    queued_syscall_returns.append(0) # password \n input

    def syscall_hook(state):
        if not state.inspect.simprocedure.is_syscall:
            print("not a syscall,return ")
            return
        try:
            f = queued_syscall_returns.pop(0)
            if f is None:
                print("f is None")
                return
            state.inspect.simprocedure_result = f(state) if callable(f) else f    # f(state) if callable(f) .
        except IndexError:
            return

    s.inspect.make_breakpoint('simprocedure', s.inspect.BP_BEFORE, action=syscall_hook)

    results = p.factory.simulation_manager(thing=s).explore(find=target_addrs[arch], avoid=avoid_addrs[arch])# target_addrs?
    print("results.found:%s" % results.found)
    if len(results.found) != 0:
        stdin = results.found[0].posix.dumps(0)
        print("stdin:%s" % stdin)
        # nose.tools.assert_equal(b'SOSNEAKY', stdin)
        stdout = results.found[0].posix.dumps(1)
        print("stdout:%s" % stdout)
        # nose.tools.assert_equal(b'HAHA\0', stdout)
    else:
        print("len(results.found) = 0")

def test_fauxware_override():
    #for arch in target_addrs:
    #   yield run_fauxware_override, arch
    yield run_fauxware_override, 'x86_64'

if __name__ == "__main__":
    #run_fauxware_override('x86_64')
    for r,a in test_fauxware_override():
        r(a)
