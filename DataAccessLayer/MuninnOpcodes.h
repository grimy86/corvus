// This file contains shared assembly opcode and instruction metadata

#ifndef MUNINN_OPCODE_DEFINITIONS_H
#define MUNINN_OPCODE_DEFINITIONS_H

#ifndef NOP_OPCODE
#define NOP_OPCODE 0x90
#endif // !NOP_OPCODE

#ifndef JMP_REL32_OPCODE
#define JMP_REL32_OPCODE 0xE9
#endif // !JMP_REL32_OPCODE

#ifndef JMP_ABS64_OPCODE
#define JMP_ABS64_OPCODE 0xFF
#endif // !JMP_ABS64_OPCODE

#ifndef JMP_ABS64_MODRM
#define JMP_ABS64_MODRM 0x25
#endif // !JMP_ABS64_MODRM

#ifndef JMP_REL32_LENGTH
#define JMP_REL32_LENGTH 5 // E9 xx xx xx xx
#endif // !JMP_REL32_LENGTH

#ifndef JMP_ABS64_LENGTH
#define JMP_ABS64_LENGTH  14  // FF 25 00 00 00 00 <8-byte addr>
#endif // !JMP_ABS64_LENGTH

#endif // !MUNINN_OPCODE_DEFINITIONS_H