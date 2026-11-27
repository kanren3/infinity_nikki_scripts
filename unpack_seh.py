"""Bounded x64 SEH search for emulated loader access violations.

Uses PE .pdata/.xdata, executes guest custom unwind handlers and C exception
filters, and honors their disposition. Never skips faulting instructions or
maps missing pages to hide failures. C++ exception personalities and machine
frames are deliberately unsupported.
"""

from bisect import bisect_right
import struct
import time

from unicorn import UcError, x86_const as x86

REGISTERS = ('RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
             'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')
CONTEXT_OFFSETS = (0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0,
                   0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0)
MASK64 = (1 << 64) - 1


class Win64Seh:
    def __init__(self, machine):
        self.m = machine
        self.tables = {}
        self.workspace = None
        self.handler_stack = None
        self.count = 0
        self.vectored = []
        self.next_vectored_handle = 1

    def capture(self):
        context = {name: self.m.uc.reg_read(getattr(x86, 'UC_X86_REG_' + name))
                   for name in (*REGISTERS, 'RIP', 'EFLAGS')}
        for i in range(16):
            context[f'XMM{i}'] = self.m.uc.reg_read(getattr(x86, f'UC_X86_REG_XMM{i}'))
        return context

    def save_context(self, address, context):
        data = bytearray(0x4d0)
        struct.pack_into('<II', data, 0x30, 0x10001f, 0x1f80)
        struct.pack_into('<H', data, 0x38, 0x33)
        struct.pack_into('<H', data, 0x42, 0x2b)
        struct.pack_into('<I', data, 0x44, context['EFLAGS'])
        debug = self.m.api.thread_debug_registers.get(self.m.current_thread, (0,) * 6)
        struct.pack_into('<6Q', data, 0x48, *debug)
        for name, offset in zip(REGISTERS, CONTEXT_OFFSETS):
            struct.pack_into('<Q', data, offset, context[name])
        struct.pack_into('<Q', data, 0xf8, context['RIP'])
        for i in range(16):
            data[0x1a0 + i * 16:0x1b0 + i * 16] = context[f'XMM{i}'].to_bytes(16, 'little')
        self.m.write(address, bytes(data))

    def load_context(self, address, context):
        data = self.m.read(address, 0x4d0)
        result = dict(context)
        for name, offset in zip(REGISTERS, CONTEXT_OFFSETS):
            result[name] = struct.unpack_from('<Q', data, offset)[0]
        result['RIP'] = struct.unpack_from('<Q', data, 0xf8)[0]
        result['EFLAGS'] = struct.unpack_from('<I', data, 0x44)[0]
        for i in range(16):
            result[f'XMM{i}'] = int.from_bytes(data[0x1a0 + i * 16:0x1b0 + i * 16], 'little')
        return result

    def restore(self, context):
        for name in (*REGISTERS, 'RIP', 'EFLAGS'):
            self.m.uc.reg_write(getattr(x86, 'UC_X86_REG_' + name), context[name])
        for i in range(16):
            self.m.uc.reg_write(getattr(x86, f'UC_X86_REG_XMM{i}'), context[f'XMM{i}'])

    def runtime_function(self, pc):
        module = self.m.module_for_address(pc)
        if module is None or module.system:
            return module, None
        if module.base not in self.tables:
            directory = module.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            raw = self.m.read(module.base + directory.VirtualAddress, directory.Size)
            entries = [(start, end, unwind, module.base + directory.VirtualAddress + i)
                       for i in range(0, len(raw) - 11, 12)
                       for start, end, unwind in [struct.unpack_from('<III', raw, i)]
                       if start and start < end]
            entries.sort()
            self.tables[module.base] = ([entry[0] for entry in entries], entries)
        starts, entries = self.tables[module.base]
        index = bisect_right(starts, pc - module.base) - 1
        if index >= 0 and pc < module.base + entries[index][1]:
            return module, entries[index]
        return module, None

    def unwind(self, module, entry, context):
        original_pc = context['RIP']
        work = dict(context)
        handler = handler_data = 0
        frame = work['RSP']
        for _ in range(16):
            start, end, unwind_rva, _ = entry
            header = self.m.read(module.base + unwind_rva, 4)
            version, flags = header[0] & 7, header[0] >> 3
            prolog, count, frameinfo = header[1:]
            if version not in (1, 2):
                raise RuntimeError(f'SEH: unsupported unwind version {version}')
            fp, fp_offset = frameinfo & 15, frameinfo >> 4
            frame = work[REGISTERS[fp]] - fp_offset * 16 if fp else work['RSP']
            codes = self.m.read(module.base + unwind_rva + 4, ((count + 1) & ~1) * 2)
            i = 0
            while i < count:
                code_offset, opinfo = codes[2*i:2*i + 2]
                op, info = opinfo & 15, opinfo >> 4
                slots = {0: 1, 1: 2 if info == 0 else 3, 2: 1, 3: 1,
                         4: 2, 5: 3, 8: 2, 9: 3}.get(op)
                if slots is None:
                    raise RuntimeError(f'SEH: unwind opcode {op} is not modeled')
                extra = codes[2*i + 2:2*(i + slots)]
                i += slots
                if original_pc - module.base - start < prolog and code_offset > original_pc - module.base - start:
                    continue
                if op == 0:
                    work[REGISTERS[info]] = self.m.u64(work['RSP'])
                    work['RSP'] += 8
                elif op == 1:
                    work['RSP'] += int.from_bytes(extra, 'little') * (8 if info == 0 else 1)
                elif op == 2:
                    work['RSP'] += info * 8 + 8
                elif op == 3:
                    work['RSP'] = frame
                elif op in (4, 5):
                    offset = int.from_bytes(extra, 'little') * (8 if op == 4 else 1)
                    work[REGISTERS[info]] = self.m.u64(frame + offset)
                elif op in (8, 9):
                    offset = int.from_bytes(extra, 'little') * (16 if op == 8 else 1)
                    work[f'XMM{info}'] = int.from_bytes(self.m.read(frame + offset, 16), 'little')
            trailer = module.base + unwind_rva + 4 + ((count + 1) & ~1) * 2
            if flags & 4:
                a, b, c = struct.unpack('<III', self.m.read(trailer, 12))
                entry = (a, b, c, trailer)
                continue
            if flags & 1 and original_pc - module.base - start >= prolog:
                handler = module.base + int.from_bytes(self.m.read(trailer, 4), 'little')
                handler_data = trailer + 4
            work['RIP'] = self.m.u64(work['RSP'])
            work['RSP'] += 8
            return work, frame, handler, handler_data
        raise RuntimeError('SEH: chained unwind limit exceeded')

    def invoke(self, address, args, deadline):
        machine = self.m
        if self.handler_stack is None:
            self.handler_stack = machine.alloc(1024 * 1024)
        saved = machine.uc.context_save()
        old_error = machine.error
        machine.error = None
        stack = self.handler_stack + 1024 * 1024 - 0x108
        machine.put64(stack, machine.sentinel)
        for i, reg in enumerate((x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX,
                                 x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)):
            machine.uc.reg_write(reg, args[i] if i < len(args) else 0)
        machine.uc.reg_write(x86.UC_X86_REG_RSP, stack)
        machine.uc.reg_write(x86.UC_X86_REG_RIP, address)
        try:
            while time.monotonic() < deadline:
                machine.uc.emu_start(machine.uc.reg_read(x86.UC_X86_REG_RIP), machine.sentinel,
                                      timeout=max(1, int((deadline - time.monotonic()) * 1e6)))
                if machine.error:
                    raise RuntimeError(f'SEH handler: {machine.error}')
                if machine.uc.reg_read(x86.UC_X86_REG_RIP) == machine.sentinel:
                    return machine.uc.reg_read(x86.UC_X86_REG_RAX) & 0xffffffff
            raise RuntimeError('SEH handler deadline exceeded')
        finally:
            machine.uc.context_restore(saved)
            machine.error = old_error

    def dispatch(self, code, access, address, deadline, *, vectored_only=False):
        machine = self.m
        if not vectored_only:
            self.count += 1
            if self.count > 4096:
                raise RuntimeError('SEH exception count limit exceeded')
        if self.workspace is None:
            self.workspace = machine.alloc(0x3000)
        exception = self.workspace
        original_ptr = exception + 0x100
        walk_ptr = exception + 0x600
        pointers = exception + 0xb00
        dispatcher = exception + 0xc00
        original = self.capture()
        self.save_context(original_ptr, original)
        record = bytearray(0x98)
        struct.pack_into('<I', record, 0, code)
        struct.pack_into('<Q', record, 0x10, original['RIP'])
        struct.pack_into('<I', record, 0x18, 2)
        struct.pack_into('<QQ', record, 0x20, access, address)
        machine.write(exception, bytes(record))
        machine.write(pointers, struct.pack('<QQ', exception, original_ptr))
        for _, handler in tuple(self.vectored):
            disposition = self.invoke(handler, (pointers,), deadline)
            if disposition == 0xffffffff:
                self.restore(self.load_context(original_ptr, original))
                machine.error = None
                return True
            if disposition != 0:
                raise RuntimeError(f'VEH: invalid handler disposition {disposition:#x}')
        if vectored_only:
            return False
        walk = dict(original)
        for _ in range(64):
            module, entry = self.runtime_function(walk['RIP'])
            if module is None:
                break
            if entry is None:
                walk['RIP'] = machine.u64(walk['RSP'])
                walk['RSP'] += 8
                continue
            before = dict(walk)
            work, frame, handler, data = self.unwind(module, entry, walk)
            if handler:
                count = int.from_bytes(machine.read(data, 4), 'little')
                scopes = []
                if 0 < count <= 128:
                    raw = machine.read(data + 4, count * 16)
                    for begin, end, filter_rva, target in struct.iter_unpack('<IIII', raw):
                        if not 0 < begin < end <= module.size:
                            scopes = []
                            break
                        scopes.append((begin, end, filter_rva, target))
                if scopes:
                    pc = before['RIP'] - module.base
                    for begin, end, filter_rva, target in scopes:
                        if not begin <= pc < end or not target:
                            continue
                        disposition = (1 if filter_rva == 1 else
                                       self.invoke(module.base + filter_rva, (pointers, frame), deadline))
                        if disposition == 0xffffffff:
                            self.restore(self.load_context(original_ptr, original))
                            machine.error = None
                            return True
                        if disposition == 1:
                            before['RSP'] = frame
                            before['RIP'] = module.base + target
                            before['RAX'] = code
                            self.restore(before)
                            machine.error = None
                            return True
                        if disposition != 0:
                            raise RuntimeError(f'SEH: invalid filter disposition {disposition:#x}')
                else:
                    self.save_context(walk_ptr, work)
                    machine.write(dispatcher, struct.pack('<QQQQQQQQII', before['RIP'], module.base,
                                  entry[3], frame, 0, walk_ptr, handler, data, 0, 0))
                    result = self.invoke(handler, (exception, frame, original_ptr, dispatcher), deadline)
                    work = self.load_context(walk_ptr, work)
                    if result == 0:  # ExceptionContinueExecution
                        self.restore(self.load_context(original_ptr, original))
                        machine.error = None
                        return True
                    if result != 1:  # ExceptionContinueSearch
                        raise RuntimeError(f'SEH: custom personality disposition {result} not modeled')
            walk = work
            if walk['RIP'] == machine.sentinel:
                break
        return False
