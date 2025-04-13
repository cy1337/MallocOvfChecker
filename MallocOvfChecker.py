#Generates a list of malloc calls using arithmetic to calculate a size
#@author Craig Young
#@category CodeAnalysis

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode, PcodeOp
from ghidra.program.model.symbol import RefType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.tablechooser import TableChooserDialog, TableChooserExecutor, AddressableRowObject

# Setup the decompiler
monitor = ConsoleTaskMonitor()
decomp_interface = DecompInterface()
decomp_interface.openProgram(currentProgram)

# Perform backward slice from a varnode
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

# Return influencing op info if ADD or MULT with variable
def find_add_or_mult_op(influencing_ops):
    for op in influencing_ops:
        if op.getOpcode() in (PcodeOp.INT_ADD, PcodeOp.INT_MULT):
            for i in range(op.getNumInputs()):
                input_var = op.getInput(i)
                if input_var is not None and not input_var.isConstant():
                    return (op.getSeqnum().getTarget(), op.getMnemonic())
    return None

# Decompile a function and check for questionable malloc calls
def check_func(func, malloc_addr):
    entries = []
    decompiled = decomp_interface.decompileFunction(func, 60, monitor)
    if not decompiled.decompileCompleted():
        return entries
    high_func = decompiled.getHighFunction()
    if high_func is None:
        return entries
    for op in high_func.getPcodeOps():
        if op.getOpcode() == PcodeOp.CALL:
            call_target = op.getInput(0).getAddress()
            if call_target != malloc_addr or op.getNumInputs() != 2:
                continue
            malloc_arg = op.getInput(1)
            influencing_ops = backward_slice(malloc_arg)
            info = find_add_or_mult_op(influencing_ops)
            if info:
                infl_addr, op_type = info
                entries.append(MallocWarning(func.getName(), op.getSeqnum().getTarget(), infl_addr, op_type))
    return entries

# Inspect currentProgram for suspicious malloc calls
def check_program():
    malloc_addr = None
    function_manager = currentProgram.getFunctionManager()
    for f in function_manager.getFunctions(True):
        if f.getName() == "malloc":
            malloc_addr = f.getEntryPoint()
            break
    if malloc_addr is None:
        print("[ * ] No malloc symbol found")
        exit()

    calling_funcs = set()
    for ref in getReferencesTo(malloc_addr):
        if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
            continue
        func = getFunctionContaining(ref.getFromAddress())
        if func is None or func in calling_funcs:
            continue
        calling_funcs.add(func)

    warnings = []
    for func in calling_funcs:
        warnings.extend(check_func(func, malloc_addr))

    if warnings:
        for w in warnings:
            print(str(w))

        class WarningExecutor(TableChooserExecutor):
            def __init__(self):
                TableChooserExecutor.__init__(self)

            def execute(self, warning):
                goTo(warning.getAddress())

            def getButtonName(self):
                return "Go To Call"

        dialog = createTableChooserDialog("Malloc Arithmetic", WarningExecutor())
        for row in warnings:
            dialog.add(row)
        dialog.show()
    else:
        print("No issues found with malloc argument calculations.")

# Represents a warning instance where a call to malloc is influenced by
# arithmetic (ADD or MULT) involving a non-constant input.
# Stores the function name, call site address, influencing operation address,
# and the type of operation that influenced the allocation size.
class MallocWarning(AddressableRowObject):
    def __init__(self, funcName, callAddr, inflAddr, opType):
        self.funcName = funcName
        self._address = callAddr
        self.inflAddr = inflAddr
        self.opType = opType

    def __str__(self):
        return "{}: call at {} influenced by {} at {}".format(self.funcName, self._address, self.opType, self.inflAddr)

    def getAddress(self):
        return self._address

check_program()
