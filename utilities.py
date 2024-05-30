# Import necessary Ghidra modules
from ghidra.program.model.mem import MemoryBlock, MemoryAccessException
from ghidra.program.model.address import Address
from ghidra.util.task import TaskMonitor
import struct

# Function to create a memory block
def create_memory_block(block_name, start_address, size):
    # Get the current program
    program = getCurrentProgram()
    
    # Get the memory object
    memory = program.getMemory()
    
    # Convert start address to an Address object
    start_addr = toAddr(start_address)
    
    # Start a transaction to make changes to the program
    transaction = program.startTransaction("Create Memory Block")
    
    try:
        # Create the memory block
        # Zero-ing the newly created block
        block = memory.createInitializedBlock(block_name, start_addr, size, None, TaskMonitor.DUMMY, False)
        
        # Set the block as read/write/execute
        block.setRead(True)
        block.setWrite(True)
        block.setExecute(True)
        
        # Commit the transaction
        program.endTransaction(transaction, True)
        print(f"Memory block '{block_name}' created successfully.")
        
    except MemoryAccessException as e:
        # If an error occurs, rollback the transaction
        program.endTransaction(transaction, False)
        print(f"Error creating memory block: {e}")

"""
block_name = "exampleBlock"
start_address = 0x400000  # Replace with your desired start address
size = 0x1000  # Replace with the size of the memory block in bytes
initial_value = 0x00  # Replace with the initial value to fill the block with

create_initialized_memory_block(block_name, start_address, size)
"""

# Read bytes from memory and store them in hex representation
# Return a list of hex bytes
def read_mem_bytes(address, size):
	byte_list = []
	
  for i in range(size):
		cur_byte = getCurrentProgram().getMemory().getByte(toAddr(address+i))
		byte_list.append(int(struct.pack('b', cur_byte).hex(),16))
	
  return byte_list


# Write a sequence of bytes into memory
# bytes_to_write should be bytearray, e.g., bytearray(b'\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') 
def write_bytes(address, bytes_to_write):
    # Get current program
    current_program = getCurrentProgram()
    address = toAddr(address)
  
    # Start a transaction to make changes to the program
    transactionID = current_program.startTransaction("Write Memory")
    try:
        # Write bytes to memory
        current_program.getMemory().setBytes(address, bytes_to_write)
        
        # Commit the changes
        current_program.endTransaction(transactionID, True)
        print("Bytes written successfully.")
    except Exception as e:
        # If an error occurs, rollback the changes
        current_program.endTransaction(transactionID, False)
        print("Error:", e)


from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def print_decompiled_code(func_name):
  program = getCurrentProgram()
  ifc = DecompInterface()
  ifc.openProgram(program)
  
  # here we assume there is only one function named `main`
  function = getGlobalFunctions(func_name)[0]
  
  # decompile the function and print the pseudo C
  results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
  print(results.getDecompiledFunction().getC())


# Enumerate all functions printing their name and address
def enumerate_functions():
  fm = currentProgram().getFunctionManager()
  
  # one-time usage, iteration will consump them out
  funcs = fm.getFunctions(True) # True means 'forward'
  
  for func in funcs: 
      print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
  
  return fm.getFunctions(True)
