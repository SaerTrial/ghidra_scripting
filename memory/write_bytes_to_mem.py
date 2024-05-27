# read bytes from a file then write to specific address
# which is quite helpful when preparing CPU and memory state for emulation, e.g., P-code

from ghidra.program.model.address import Address
from ghidra.util.task import TaskMonitor
import array
import os

def read_file_to_bytearray(filename):
    with open(filename, 'rb') as file:
        # Read all bytes from the file
        file_bytes = file.read()
        
        # Create a bytearray and append all bytes to it
        byte_array = bytearray()
        byte_array.extend(file_bytes)
        
    return byte_array


def write_bytes(address, bytes_to_write):
    # Get current program
    current_program = getCurrentProgram()
    
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

# Example usage:
# Specify the address where you want to write the bytes
address_to_write = toAddr(0x8000000)  # Replace 0x2000 with your desired address

# .data	00441000	004443b7	0x33b8	true	true	false	false		Default	true			
# Specify the bytes you want to write
fw_path = os.path.join(os.path.expanduser("~"),"Downloads","encrypted_fw")

#bytes_to_write = bytearray(b'\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')  # Replace with your desired bytes
bytes_to_write = read_file_to_bytearray(fw_path)
print(len(bytes_to_write))

# Call the function to write bytes
write_bytes(address_to_write, bytes_to_write)
