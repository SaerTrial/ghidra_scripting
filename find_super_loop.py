
# find an infinite loop through the current binary
# which is quite useful to locate main function of firmware.

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)


pattern = r"while.*(.*true.*)"

fm = currentProgram().getFunctionManager()
# one-time usage, iteration will consump them out
funcs = fm.getFunctions(True) # True means 'forward'
for func in funcs: 
		function = getGlobalFunctions(func.getName())[0]
		results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
		
		if re.findall(pattern, results.getDecompiledFunction().getC()):
	    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
    
