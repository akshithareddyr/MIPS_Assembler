import time
import re

def binary_to_hex(binary_str):
    """Converts a binary string to its hexadecimal representation."""
    hex_str = ''
    for i in range(0, len(binary_str), 4):
        hex_str += hex(int(binary_str[i:i+4], 2))[2:].upper()
    return hex_str

VALID_MNEMONICS = {
    # R-type instructions
    'add': 'R', 'addu': 'R', 'sub': 'R', 'subu': 'R', 'and': 'R', 'or': 'R', 'xor': 'R', 'nor': 'R',
    'slt': 'R', 'sltu': 'R', 'sll': 'R_shamt', 'srl': 'R_shamt', 'sra': 'R_shamt', 'sllv': 'R', 'srlv': 'R', 'srav': 'R',
    'mult': 'R', 'multu': 'R', 'div': 'R', 'divu': 'R', 'mfhi': 'R_single', 'mflo': 'R_single',
    'mthi': 'R_single', 'mtlo': 'R_single', 'jr': 'R_single', 'jalr': 'R_jalr', 'syscall': 'R_syscall', 'nop': 'R_single',

    # I-type instructions
    'addi': 'I', 'addiu': 'I', 'andi': 'I', 'ori': 'I', 'xori': 'I', 'slti': 'I', 'sltiu': 'I',
    'lui': 'I', 'lw': 'I', 'lh': 'I', 'lhu': 'I', 'lb': 'I', 'lbu': 'I', 'sw': 'I', 'sh': 'I', 'sb': 'I',
    'beq': 'I', 'bne': 'I', 'blez': 'I_single', 'bgtz': 'I_single',

    # J-type instructions
    'j': 'J', 'jal': 'J'
}
# First pass function with duplicate label check
def first_pass(assembly_code):

    symbol_table = {}
    commands = []
    addresses = []
    address = 0
    #The strip() method removes any leading and trailing whitespace characters from the
    #string line. This includes spaces, tabs (\t), and newlines (\n).

    for line in assembly_code:
        line = line.strip()

        if len(line) == 0:
            continue

        if ':' in line:
            label, command = line.split(':', 1)
            label = label.strip()

            if label.lower() in VALID_MNEMONICS:
                raise ValueError(f"Error: Label '{label}' is a mnemonic")

            # Check for duplicate labels
            if label in symbol_table:
                raise ValueError(f"Error: Duplicate label '{label}' found at address {address}")

            symbol_table[label] = address

            if command.strip():
                cleaned_command = re.sub(r'\s+', ' ', command.strip())
                cleaned_command = re.sub(r'\s*,\s*', ', ', cleaned_command)  # Ensure correct comma spacing
                commands.append(cleaned_command)
                addresses.append(address)
                address += 4
        else:
            cleaned_command = re.sub(r'\s+', ' ', line)
            cleaned_command = re.sub(r'\s*,\s*', ', ', cleaned_command)  # Ensure correct comma spacing
            commands.append(cleaned_command)
            addresses.append(address)
            address += 4

    return symbol_table, commands, addresses

instruction_set = {
                    "add": {"format": "R", "opcode": 0, "shamt": 0, "func": 32},
                    "sub": {"format": "R", "opcode": 0, "shamt": 0, "func": 34},
                    "and": {"format": "R", "opcode": 0, "shamt": 0, "func": 36},
                    "jr": {"format": "R", "opcode": 0, "shamt": 0, "func": 8},
                    "mfhi": {"format": "R", "opcode": 0, "shamt": 0, "func": 16},
                    "mthi": {"format": "R", "opcode": 0, "shamt": 0, "func": 17},
                    "nor": {"format": "R", "opcode": 0, "shamt": 0, "func": 39},
                    "or": {"format": "R", "opcode": 0, "shamt": 0, "func": 37},
                    "slt": {"format": "R", "opcode": 0, "shamt": 0, "func": 42},
                    "sltu": {"format": "R", "opcode": 0, "shamt": 0, "func": 43},
                    "sll": {"format": "R", "opcode": 0, "shamt": 0, "func": 0},
                    "srl": {"format": "R", "opcode": 0, "shamt": 0, "func": 2},
                    "addi": {"format": "I", "opcode": 8, "type": 1},
                    "addiu": {"format": "I", "opcode": 9, "type": 1},
                    "xori": {"format": "I", "opcode": 14, "type": 1},
                    "andi": {"format": "I", "opcode": 12, "type": 1},
                    "beq": {"format": "I", "opcode": 4, "type": 2},
                    "bne": {"format": "I", "opcode": 5, "type": 2},
                    "lb": {"format": "I", "opcode": 32, "type": 3},
                    "lbu": {"format": "I", "opcode": 36, "type": 3},
                    "ll": {"format": "I", "opcode": 48, "type": 3},
                    "sc": {"format": "I", "opcode": 56, "type": 3},
                    "lh": {"format": "I", "opcode": 33, "type": 3},
                    "lhu": {"format": "I", "opcode": 37, "type": 3},
                    "lui": {"format": "I", "opcode": 15, "type": 4},
                    "lw": {"format": "I", "opcode": 35, "type": 3},
                    "ori": {"format": "I", "opcode": 13, "type": 1},
                    "sb": {"format": "I", "opcode": 40, "type": 3},
                    "slti": {"format": "I", "opcode": 10, "type": 1},
                    "sltiu": {"format": "I", "opcode": 11, "type": 1},
                    "sh": {"format": "I", "opcode": 41, "type": 3},
                    "sw": {"format": "I", "opcode": 43, "type": 3},
                    "j": {"format": "J", "opcode": 2},
                    "jal": {"format": "J", "opcode": 3},
                    "addu": {"format": "R", "opcode": 0, "shamt": 0, "func": 33},
                    "subu": {"format": "R", "opcode": 0, "shamt": 0, "func": 35},
                    "xor": {"format": "R", "opcode": 0, "shamt": 0, "func": 38},
                    "sra": {"format": "R", "opcode": 0, "shamt": 0, "func": 3},
                    "sllv": {"format": "R", "opcode": 0, "shamt": 0, "func": 4},
                    "srlv": {"format": "R", "opcode": 0, "shamt": 0, "func": 6},
                    "srav": {"format": "R", "opcode": 0, "shamt": 0, "func": 7},
                    "mult": {"format": "R", "opcode": 0, "shamt": 0, "func": 24},
                    "multu": {"format": "R", "opcode": 0, "shamt": 0, "func": 25},
                    "div": {"format": "R", "opcode": 0, "shamt": 0, "func": 26},
                    "divu": {"format": "R", "opcode": 0, "shamt": 0, "func": 27},
                    "mflo": {"format": "R", "opcode": 0, "shamt": 0, "func": 18},
                    "mtlo": {"format": "R", "opcode": 0, "shamt": 0, "func": 19},
                    "jalr": {"format": "R", "opcode": 0, "shamt": 0, "func": 9},
                    "blez": {"format": "I", "opcode": 6, "type": 4},
                    "bgtz": {"format": "I", "opcode": 7, "type": 4},
                    "jalr": {"format": "R","opcode": 0,"shamt": 0,"func": 9},
                    "syscall": {"format": "R", "opcode": 0, "func": 12},
                    "nop" : {"format": "R", "opcode": 0, "shamt": 0, "func": 0}

                }

def second_pass(commands, symbol_table, instruction_set, registers, max_address):

    machine_code = []
    address_map = {}  

    r_count = 0
    i_count = 0
    j_count = 0
    address = 0
    

    for idx, command in enumerate(commands):
        address_map[command] = address
        address += 4  

    for line_num, command in enumerate(commands, start=1):
        parts = command.split()
        instr = parts[0]  # The instruction (e.g., add, lw, etc.)
        instr = instr.lower()
        # Check if the mnemonic is valid
        if instr.lower() == 'nop':
          machine_code.append('00000000000000000000000000000000')  # 32-bit 0 for NOP
          continue

        if instr not in instruction_set:
            raise ValueError(f"Error: Invalid mnemonic '{instr}' found in command '{command}'at instruction number {line_num}.")
        instr_info = instruction_set[instr]
        instr_format = instr_info['format']

        if instr_format == 'R':  # R-format instructions
          try:

            # Check if the instruction is a shift operation
            if instr in {'sll', 'srl', 'sra'}:  
                if len(parts) != 4:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 3 operand, got {len(parts) - 1}.")
                rd = registers[parts[1].strip(',')]
                rs = 0  
                rt = registers[parts[2].strip(',')]  
                shamt = int(parts[3]) 

            elif instr in {'mult', 'multu', 'div', 'divu'}:
                if len(parts) != 3:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 2 operand, got {len(parts) - 1}.")
                rd = 0
                rs = registers[parts[1].strip(',')]
                rt = registers[parts[2].strip(',')]
                shamt = instr_info['shamt']

            elif instr in {'mfhi', 'mthi', 'mflo', 'mtlo'}:
                if len(parts) != 2:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 1 operand, got {len(parts) - 1}.")
                if instr in {'mfhi' , 'mflo'}:
                    rd = registers[parts[1].strip(',')]
                    rs = 0
                    rt = 0
                    shamt = 0
                else:
                    rd = 0
                    rt = 0
                    rs = registers[parts[1].strip(',')]
                    shamt = 0
            elif instr == 'jalr':
                    if len(parts) != 2 and len(parts) != 3:
                        raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected either 1 or 2 operands, got {len(parts) - 1}.")
                    if len(parts) == 2:
                      rd = 31
                      rs = registers[parts[1].strip(',')]
                      rt = 0
                      shamt = 0
                    elif len(parts) == 3:
                      rd = registers[parts[1].strip(',')]
                      rs = registers[parts[2].strip(',')]
                      rt = 0
                      shamt = 0
            elif instr == 'jr':
                    if len(parts) != 2:
                        raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 1 operand, got {len(parts) - 1}.")

                    rd = 0
                    rs = registers[parts[1].strip(',')]
                    rt = 0
                    shamt = 0
            elif instr == 'syscall':
                    if len(parts) != 1:
                        raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 0 operand, got {len(parts) - 1}.")
                    rd = 0
                    rs = 0
                    rt = 0
                    shamt = 0
                    func = 12
            else:
                if len(parts) != 4:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 3 operand, got {len(parts) - 1}.")
                rd = registers[parts[1].strip(',')]
                rs = registers[parts[2].strip(',')]
                rt = registers[parts[3].strip(',')]
                shamt = instr_info['shamt']  

          except KeyError as e:
            raise ValueError(f"Error: Invalid register '{e.args[0]}' in command '{command}' at instruction number {line_num}.")

          func = instr_info['func']
          opcode = instr_info['opcode']
          machine_instr = (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | func
          machine_code.append(f"{machine_instr:032b}")
          r_count += 1

        elif instr_format == 'I':  # I-format instructions
            rt = registers.get(parts[1].strip(','), None)

            if rt is None:
                raise ValueError(f"Error: Invalid target register '{parts[1].strip(',')}' in command '{command}'at instruction number {line_num}.")

            if instr_info['type'] == 1:  # Immediate instructions
                if len(parts) != 4:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 3 operand, got {len(parts) - 1}.")
                rs = registers.get(parts[2].strip(','), None)
                if rs is None:
                    raise ValueError(f"Error: Invalid source register '{parts[2].strip(',')}' in command '{command}' at instruction number {line_num}.")
                imm = int(parts[3])  # Immediate value

                if imm < -32768 or imm > 32767:
                    raise ValueError(f"Error: Immediate value '{imm}' out of range (-32768 to 32767) in command '{command}' at instruction number {line_num}.")

            elif instr_info['type'] == 2:  # Branch instructions
                if len(parts) != 4:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 3 operand, got {len(parts) - 1}.")
                rs = registers.get(parts[1].strip(','), None)
                if rs is None:
                    raise ValueError(f"Error: Invalid source register '{parts[1].strip(',')}' in command '{command}' at instruction number {line_num}.")
                rt = registers.get(parts[2].strip(','), None)
                if rt is None:
                    raise ValueError(f"Error: Invalid target register '{parts[2].strip(',')}' in command '{command}' at instruction number {line_num}.")
                label_or_address = parts[3]
                if label_or_address in symbol_table:

                    # Case 1: It's a label
                    imm = (symbol_table[label_or_address] - (address_map[command] + 4)) // 4
                else:

                    # Case 2: Check if it's a valid address (numeric and multiple of 4)
                    try:
                        if label_or_address.startswith("0x") or label_or_address.startswith("0X"):
                            address_value = int(label_or_address, 16)
                        else:
                            address_value = int(label_or_address)
                        if address_value % 4 != 0:
                            raise ValueError(f"Error: Address '{address_value}' is not a multiple of 4 in command '{command}' at instruction number {line_num}.")
                        if not (0 <= address_value <= max_address):
                            raise ValueError(f"Error: Address '{address_value}' is out of the valid program range (0 to {max_address}) in command '{command}' at instruction number {line_num}.")

                        # Calculate immediate value as offset in instructions
                        imm = (address_value - (address_map[command] + 4)) // 4
                    except ValueError:
                        raise ValueError(f"Error: '{label_or_address}' is neither a valid label nor a valid address in command '{command}' at instruction number {line_num}.")
                if imm < -32768 or imm > 32767:
                    raise ValueError(f"Error: Calculated immediate '{imm}' out of range (-32768 to 32767) in command '{command}' at instruction number {line_num}.")

            elif instr_info['type'] == 3:  # Load/store instructions
                if len(parts) != 3:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 2 operand, got {len(parts) - 1}.")
                imm, reg = parts[2].split('(')
                imm = int(imm)
                if imm < -32768 or imm > 32767:
                    raise ValueError(f"Error: Immediate value '{imm}' out of range (-32768 to 32767) in command '{command}' at instruction number {line_num}.")

                rs = registers.get(reg.strip(')'), None)
                if rs is None:
                    raise ValueError(f"Error: Invalid base register '{reg.strip(')')}' in command '{command}' at instruction number {line_num}.")

            elif instr_info['type'] == 4:  # Load upper immediate or Branch instructions with single register
                if len(parts) != 3:
                    raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 2 operand, got {len(parts) - 1}.")
                rs = 0
                # Check if the operand is a label
                if parts[2] in symbol_table:
                    # It's a label, calculate relative address
                    imm = (symbol_table[parts[2]] - (address_map[command] + 4)) // 4
                else:
                    # It's assumed to be an immediate value, convert to integer
                    try:
                        imm = int(parts[2])
                    except ValueError:
                        raise ValueError(f"Error: Invalid immediate value or label '{parts[2]}' in command '{command}' at instruction number {line_num}.")

                if imm < -32768 or imm > 32767:
                    raise ValueError(f"Error: Immediate value '{imm}' out of range (-32768 to 32767) in command '{command}' at instruction number {line_num}.")
            opcode = instr_info['opcode']
            machine_instr = (opcode << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
            machine_code.append(f"{machine_instr:032b}")
            i_count += 1

        elif instr_format == 'J':  # J-format instructions
            if len(parts) != 2:
                raise ValueError(f"Error: Incorrect number of operands in command '{command}' at instruction number {line_num}. Expected 1 operand, got {len(parts) - 1}.")
            target_str = parts[1]
            if target_str in symbol_table:
                # It's a label
                target = symbol_table[target_str] >> 2
            else:
                try:
                    # Try to interpret it as a direct address
                    if target_str.startswith("0x") or target_str.startswith("0X"):
                        target = int(target_str, 16)# Convert hexadecimal to decimal
                    else:
                        target = int(target_str)# Interpret as decimal

                    if target % 4 != 0:
                        raise ValueError(f"Error: Address '{target}' is not a multiple of 4 in command '{command}' at instruction number {line_num}.")
                    if not (0 <= target <= max_address):
                        raise ValueError(f"Error: Address '{target}' is out of the valid program range (0 to {max_address}) in command '{command}' at instruction number {line_num}.")
                    target //= 4  # Convert to word address
                except ValueError:
                    raise ValueError(f"Error: '{target_str}' is neither a valid label nor a valid address in command '{command}' at instruction number {line_num}.")

            opcode = instr_info['opcode']
            machine_instr = (opcode << 26) | (target & 0x3FFFFFF)
            machine_code.append(f"{machine_instr:032b}")
            j_count += 1

    return machine_code, r_count, i_count, j_count


# Define the register dictionary
registers = {
    '$0': 0, '$zero': 0, '$at': 1, '$v0': 2, '$v1': 3, '$a0': 4, '$a1': 5,
    '$a2': 6, '$a3': 7, '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11, '$t4': 12,
    '$t5': 13, '$t6': 14, '$t7': 15, '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19,
    '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23, '$t8': 24, '$t9': 25, '$k0': 26,
    '$k1': 27, '$gp': 28, '$sp': 29, '$fp': 30, '$ra': 31
}

from tabulate import tabulate
def display_machine_code(commands, machine_code, addresses):
    table_data = []
    for addr, cmd, mc in zip(addresses, commands, machine_code):
        table_data.append([f"{addr:08X}", cmd, mc, binary_to_hex(mc)])
    headers = [" Address", "Command", "Machine Code (Binary)     ", "Machine Code (Hex)"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

import time
import sys

def assembler(input_file, output_file):
    
    with open(input_file, 'r') as file:
        assembly_code = [line.split('#')[0].strip() for line in file if line.strip() and not line.startswith('#')]

    start_time = time.time()
    symbol_table, commands, addresses = first_pass(assembly_code)
    print("Symbol Table:", symbol_table)
    print("Commands:", commands)
    print("Addresses:", addresses)

    max_address = addresses[-1]
    machine_code, r_count, i_count, j_count = second_pass(commands, symbol_table, instruction_set, registers, max_address)
    display_machine_code(commands, machine_code, addresses)
    print("Number of labels:", len(symbol_table))
    tot_inst = r_count + i_count + j_count
    print("No. of R_type instructions:" ,r_count)
    print("No. of I_type instructions:" ,i_count)
    print("No. of J_type instructions:" ,j_count)
    print("Total no of instructions:", tot_inst)
    
    end_time = time.time()
    execution_time = end_time - start_time

    print("Execution Time:", execution_time, "seconds")
    print("Throughput is:", tot_inst / execution_time, "instructions per second")

    with open(output_file, "wb") as bin_file:
        for instruction in machine_code:
            instruction_int = int(instruction, 2)
            bin_file.write(instruction_int.to_bytes(4, byteorder='big'))

    print(f"Binary file '{output_file}' created successfully!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python assembler.py <input_file.asm> <output_file.bin>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    assembler(input_file, output_file)
