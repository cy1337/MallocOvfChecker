# Introduction

In this guide, I will explain how to implement a script for flagging `malloc` calls as possibly prone to integer overflow. This will use Ghidra's Python API API Python script which flags `malloc` calls as potentially being prone to integer wraparound.  To achieve this, the script will identify each malloc call and how the `size` parameter was defined. For the purpose of this basic script, we will flag any `size` argument that was calculated through addition or multiplication with a variable. 

It's possible to do this with ease by leveraging the structure of Ghidra’s PCode intermediate language. PCode represents values within a program as variable nodes (varnodes) where each varnode is only set once. This allows us to get a clear picture of where values come from and what operations or instructions influence the value. 

# Implementation
The script enumerates and decompiles functions that call `malloc`. The PCode is accessed by calling `getHighFunction()` on the decompiled function:
```py
high_func = decompiled.getHighFunction()
```

The PCode is then searched for calls to `malloc` similar to:
```py
for op in high_func.getPcodeOps():
    if op.getOpcode() == PcodeOp.CALL:
        if op.getInput(0).getAddress() == malloc_addr:
            # op is a call to malloc
            # op.getInput(1) is the varnode for size parameter
```

The script then builds a list of definition dependencies for each varnode corresponding to a `malloc` size argument. The result is a list of the pcode ops which influence the size parameter. This is achieved using recursion similar to the following:
```py
def backward_slice(varnode, visited=None, collected=None):
    if visited is None:
        visited = set()
    if collected is None:
        collected = set()
    if varnode is None or varnode in visited:
        return collected
    visited.add(varnode)
    def_op = varnode.getDef()
    if def_op:
        collected.add(def_op)
        for i in range(def_op.getNumInputs()):
            backward_slice(def_op.getInput(i), visited, collected)
    return collected
```

Finally, the script has to search through the constructed chains to see if any of the operations involved addition or multiplication with a variable. This is done by iterating over the list, checking if any op is an `INT_ADD` or `INT_MULT`, and then further checking that there is a non-constant input:
```py
def has_variable_add_or_mult(influencing_ops):
    for op in influencing_ops:
        if op.getOpcode() in (PcodeOp.INT_ADD, PcodeOp.INT_MULT):
            for i in range(op.getNumInputs()):
                input_var = op.getInput(i)
                if input_var is not None and not input_var.isConstant():
                    return True
    return False
```

# Example Usage
A completed version of the script is on GitHub. When run, this version of the script will create a table with the address of each flagged `malloc` along with console output containing more details about why each call was flagged.

Running this on a sample program produces the following text on the console:
```
FUN_001b75fb: call at 001b77e5 influenced by INT_ADD at 001b77de
FUN_001b532e: call at 001b5360 influenced by INT_ADD at 001b5358
FUN_0052dfd0: call at 0052e003 influenced by INT_ADD at 0052dfff
FUN_005e32b0: call at 005e32bd influenced by INT_MULT at 005e32ba
FUN_005e1600: call at 005e1609 influenced by INT_MULT at 005e1606
FUN_005e1650: call at 005e1755 influenced by INT_ADD at 005e174e
FUN_005e20e0: call at 005e2149 influenced by INT_ADD at 005e2144
FUN_001b5d56: call at 001b5da6 influenced by INT_ADD at 001b5d9f
FUN_005e2280: call at 005e2325 influenced by INT_MULT at 005e231b
```

