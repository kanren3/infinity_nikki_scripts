"""Win64 loader-startup APIs for one isolated, deterministic guest thread.

Win64Api never calls native DLLs, accesses host handles, or runs callbacks.
The guest has an empty environment, a console, one process heap and a virtual
clock. Module lookup and bounded emulated memory are supplied by the machine.
Unsupported operations stop emulation instead of claiming to have succeeded.
"""

import json
from pathlib import Path, PureWindowsPath
import struct
import unicodedata
from unicorn import UcError


MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
PAGE = 0x1000
FILETIME_EPOCH = 132539328000000000  # 2021-01-01 UTC
MAX_TEXT = 1 << 20  # refuse unusually large conversions; never truncate them
INVALID_PARAMETER = 87
INSUFFICIENT_BUFFER = 122
STATUS_INVALID_PARAMETER = 0xc000000d
STATUS_INVALID_HANDLE = 0xc0000008
STATUS_NO_MEMORY = 0xc0000017
STATUS_MEMORY_NOT_ALLOCATED = 0xc00000a0
STATUS_INVALID_PAGE_PROTECTION = 0xc0000045
# PAGE_* to Unicorn's read/write/execute bits. No host-native memory involved.
PROTECTION = {1: 0, 2: 1, 4: 3, 8: 3, 0x10: 4, 0x20: 5, 0x40: 7, 0x80: 7}
DEFAULT_PROTECTION = {0: 1, 1: 2, 3: 4, 4: 0x10, 5: 0x20, 7: 0x40}
# The emulated locale is en-US; CP_ACP=1252, CP_OEMCP=437.
CODEPAGES = {437: ('cp437', 1, b''), 65001: ('utf-8', 4, b''),
             20127: ('ascii', 1, b''), 932: ('cp932', 2, b'\x81\x9f\xe0\xfc'),
             936: ('gbk', 2, b'\x81\xfe'), 949: ('cp949', 2, b'\x81\xfe'),
             950: ('cp950', 2, b'\x81\xfe'),
             **{cp: (f'cp{cp}', 1, b'') for cp in range(1250, 1259)}}

# Microsoft-published best-fit table, stored locally for offline emulation.
CP1252_BESTFIT = {int(key, 16): value for key, value in
                 json.loads(Path(__file__).with_name('windows1252.json').read_text(encoding='utf-8'))['mapping'].items()}


def page_up(n):
    return (n + PAGE - 1) & -PAGE


def signed32(n):
    return (n & MASK32) - ((n & 0x80000000) << 1)


def require_flags(value, supported, api):
    if value & ~supported:
        raise RuntimeError(f'{api}: unsupported flags {value:#x}')


class Win64Api:
    def __init__(self, machine):
        self.m = machine
        self.buffers = {}
        self.heap_blocks = {}
        self.private_heaps = set()
        self.heap_owners = {}
        self.heap_bins = {}
        self.heap_cursor = self.heap_end = 0
        self.virtual_blocks = {}
        self.protections = {}
        self.tls = {}
        self.fls = {}
        self.fls_values = {}
        self.thread_handles = {}
        self.kernel_events = {}
        self.srw_owners = {}
        self.hidden_threads = set()
        self.thread_debug_registers = {}
        self.com_apartments = {}
        self.snapshots = {}
        self.atoms = {}
        self.next_atom = 0xc000
        self.timer_handles = {}
        self.token_handles = {}
        self.critical = set()
        self.srw = {}
        self.mutex_handles = {}
        self.named_mutexes = {}
        self.file_handles = {}
        self.mapping_handles = {}
        self.file_views = {}
        self.temp_files = {}
        self.events = {}
        self.next_handle = 0x400
        self.console = {-10: 0x104, -11: 0x108, -12: 0x10c}
        self.stack_guarantee = 0

    def _error(self, code, result=0):
        self.m.set_last_error(code)
        return result

    def _copy(self, dst, src, count):
        for offset in range(0, count, 65536):
            self.m.write(dst + offset, self.m.read(src + offset, min(65536, count - offset)))

    def _clock(self):
        self.m.time_counter += 10000  # 1ms expressed in 100ns QPC/FILETIME units
        ticks = self.m.time_counter
        for offset, value in ((8, ticks), (0x14, FILETIME_EPOCH + ticks), (0x320, ticks // 10000)):
            self.m.write(0x7ffe0000 + offset, struct.pack('<III', value & MASK32, value >> 32, value >> 32))
        return self.m.time_counter

    def _id(self, thread=False):
        return self.m.u64(self.m.teb + (0x48 if thread else 0x40)) & MASK32 or 1

    def _buffer(self, key, data):
        if key not in self.buffers:
            ptr = self.m.alloc(len(data))
            self.m.write(ptr, data)
            self.buffers[key] = ptr
        return self.buffers[key]

    def _heap(self):
        heap = self.m.u64(self.m.peb + 0x30)
        if not heap:
            heap = self.m.alloc(PAGE)
            self.m.put64(self.m.peb + 0x30, heap)
        return heap

    def _heap_alloc(self, n, zero=False):
        capacity = (max(1, n) + 15) & -16
        pooled = capacity <= 65536
        if pooled:
            available = self.heap_bins.get(capacity)
            if available:
                ptr = available.pop()
            else:
                if self.heap_cursor + capacity > self.heap_end:
                    self.heap_cursor = self.m.alloc(1024 * 1024)
                    self.heap_end = self.heap_cursor + 1024 * 1024
                ptr = self.heap_cursor
                self.heap_cursor += capacity
        else:
            ptr = self.m.alloc(capacity)
        self.heap_blocks[ptr] = (n, capacity, pooled)
        if zero:
            self._zero(ptr, n)
        return ptr

    def _heap_free(self, ptr):
        _, capacity, pooled = self.heap_blocks.pop(ptr)
        if pooled:
            self.heap_bins.setdefault(capacity, []).append(ptr)
        else:
            self.m.free(ptr)

    def _heap_call(self, name, a):
        m = self.m
        flags = a(1) & MASK32
        if a(0) != self._heap() and a(0) not in self.private_heaps:
            return MASK64 if name == 'Size' else 0
        require_flags(flags, {'Alloc': 9, 'ReAlloc': 0x19, 'Size': 1, 'Free': 1}[name], 'Heap' + name)
        if name == 'Alloc':
            ptr = self._heap_alloc(a(2), bool(flags & 8))
            self.heap_owners[ptr] = a(0)
            return ptr
        ptr = a(2)
        if ptr not in self.heap_blocks or self.heap_owners.get(ptr) != a(0):
            return MASK64 if name == 'Size' else int(name == 'Free' and not ptr)
        requested, capacity, _ = self.heap_blocks[ptr]
        if name == 'Size':
            return requested
        if name == 'Free':
            self._heap_free(ptr)
            self.heap_owners.pop(ptr, None)
            return 1
        n = a(3)
        if n <= capacity:
            if flags & 8 and n > requested:
                self._zero(ptr + requested, n - requested)
            self.heap_blocks[ptr] = (n, capacity, self.heap_blocks[ptr][2])
            return ptr
        if flags & 0x10:  # HEAP_REALLOC_IN_PLACE_ONLY
            return 0
        new = self._heap_alloc(n, bool(flags & 8))
        self._copy(new, ptr, min(requested, n))
        self.heap_owners[new] = a(0)
        self.heap_owners.pop(ptr, None)
        self._heap_free(ptr)
        return new

    def _zero(self, addr, count):
        zeros = bytes(min(65536, count))
        for offset in range(0, count, 65536):
            self.m.write(addr + offset, zeros[:min(65536, count - offset)])

    def _protect(self, addr, size, protection):
        if protection not in PROTECTION:
            return STATUS_INVALID_PAGE_PROTECTION, 0
        if not addr or not size or addr + size > MASK64:
            return STATUS_INVALID_PARAMETER, 0
        first, end = addr & -PAGE, page_up(addr + size)
        cur, old = first, 0
        for lo, hi, perms in sorted(self.m.uc.mem_regions()):
            if hi < cur:
                continue
            if lo > cur:
                break
            if cur == first:
                old = self.protections.get(first, DEFAULT_PROTECTION.get(perms))
                if old is None:
                    raise RuntimeError(f'no Win64 equivalent for guest permissions {perms:#x}')
            cur = hi + 1
            if cur >= end:
                self.m.uc.mem_protect(first, end - first, PROTECTION[protection])
                for p in range(first, end, PAGE):
                    self.protections[p] = protection
                return 0, old
        return STATUS_MEMORY_NOT_ALLOCATED, 0

    def _virtual(self, kind, a):
        m = self.m
        if a(0) != MASK64:
            return STATUS_INVALID_HANDLE
        bp = a(1)
        sp = a(3 if kind == 'Allocate' else 2)
        if not bp or not sp:
            return STATUS_INVALID_PARAMETER
        addr, size = m.u64(bp), m.u64(sp)
        base, end = addr & -PAGE, page_up(addr + size)
        if addr + size > MASK64:
            return STATUS_INVALID_PARAMETER
        if kind == 'Protect':
            if not a(4):
                return STATUS_INVALID_PARAMETER
            status, old = self._protect(addr, size, a(3) & MASK32)
            if status:
                return status
            m.put32(a(4), old)
        elif kind == 'Allocate':
            flags, prot = a(4) & MASK32, a(5) & MASK32
            if not size or flags not in (0x1000, 0x2000, 0x3000):
                return STATUS_INVALID_PARAMETER
            if prot not in PROTECTION:
                return STATUS_INVALID_PAGE_PROTECTION
            if a(2):
                raise RuntimeError('NtAllocateVirtualMemory: nonzero ZeroBits not modeled')
            if addr:
                if flags != 0x1000 or not any(lo <= base and end <= lo + n for lo, n in self.virtual_blocks.items()):
                    raise RuntimeError('NtAllocateVirtualMemory: placement outside existing reservation')
            else:
                base = m.alloc(size)
                if not base:
                    return STATUS_NO_MEMORY
                end = base + page_up(size)
                self.virtual_blocks[base] = end - base
            status, _ = self._protect(base, end - base, prot if flags & 0x1000 else 1)
            if status:
                return status
        else:
            flags = a(3) & MASK32
            if flags == 0x8000:
                if size:
                    return STATUS_INVALID_PARAMETER
                if addr not in self.virtual_blocks or not m.free(addr):
                    return STATUS_MEMORY_NOT_ALLOCATED
                end = base + self.virtual_blocks.pop(addr)
                for p in range(base, end, PAGE):
                    self.protections.pop(p, None)
            elif flags == 0x4000:
                if not size and base == addr and addr in self.virtual_blocks:
                    end = base + self.virtual_blocks[base]
                if end <= base or not any(lo <= base and end <= lo + n for lo, n in self.virtual_blocks.items()):
                    return STATUS_MEMORY_NOT_ALLOCATED
                self._zero(base, end - base)
                self._protect(base, end - base, 1)
            else:
                return STATUS_INVALID_PARAMETER
        m.put64(bp, base)
        m.put64(sp, end - base)
        return 0

    def _text(self, ptr, length, wide):
        if length == -1:
            return self.m.cstr(ptr, wide=wide) + '\0' if wide else self._cstring_bytes(ptr) + b'\0'
        if length > MAX_TEXT:
            raise RuntimeError('guest string exceeds conversion limit')
        data = self.m.read(ptr, length * (2 if wide else 1))
        return data.decode('utf-16-le', 'surrogatepass') if wide else data

    def _cstring_bytes(self, ptr):
        out = bytearray()
        while len(out) < MAX_TEXT:
            n = min(PAGE - (ptr % PAGE), MAX_TEXT - len(out))
            chunk = self.m.read(ptr, n)
            end = chunk.find(b'\0')
            if end >= 0:
                out.extend(chunk[:end])
                return bytes(out)
            out.extend(chunk)
            ptr += n
        raise RuntimeError('unterminated or oversized guest string')

    def _output(self, buf, capacity, data, unit):
        n = len(data) // unit
        if capacity:
            if not buf or capacity < 0:
                return self._error(INVALID_PARAMETER)
            if capacity < n:
                return self._error(INSUFFICIENT_BUFFER)
            self.m.write(buf, data)
        return n

    @staticmethod
    def _page(cp):
        return CODEPAGES.get({0: 1252, 1: 437, 3: 1252}.get(cp, cp))

    def _convert(self, name, a):
        cp, flags, src = a(0) & MASK32, a(1) & MASK32, a(2)
        length, dst, cap = signed32(a(3)), a(4), signed32(a(5))
        page = self._page(cp)
        if not page or not src or length == 0 or length < -1 or cap < 0 or (cap and (not dst or src == dst)):
            return self._error(INVALID_PARAMETER)
        codec, _, _ = page
        wide = name == 'WideCharToMultiByte'
        text = self._text(src, length, wide)
        try:
            if not wide:
                require_flags(flags, 9, name)  # MB_PRECOMPOSED | MB_ERR_INVALID_CHARS
                if codec == 'cp1252':
                    decoded = ''.join(chr(b) if b in (0x81, 0x8d, 0x8f, 0x90, 0x9d)
                                      else bytes((b,)).decode(codec) for b in text)
                else:
                    decoded = text.decode(codec, 'strict' if flags & 8 else 'replace')
                data = decoded.encode('utf-16-le')
                return self._output(dst, cap, data, 2)
            if codec == 'utf-8':
                if a(6) or a(7) or flags not in (0, 0x80):
                    return self._error(INVALID_PARAMETER)
                if not flags:
                    text = text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'replace')
                return self._output(dst, cap, text.encode('utf-8'), 1)
            require_flags(flags, 0x400, name)  # WC_NO_BEST_FIT_CHARS
            used = False
            replacement = self.m.read(a(6), 1) if a(6) else b'?'
            if a(6) and page[1] > 1:
                raise RuntimeError(f'{name}: custom DBCS replacement not modeled')
            out = bytearray()
            for ch in text:
                if codec == 'cp1252' and not flags & 0x400 and ord(ch) in CP1252_BESTFIT:
                    out.append(CP1252_BESTFIT[ord(ch)])
                    continue
                try:
                    if codec == 'cp1252' and ord(ch) in (0x81, 0x8d, 0x8f, 0x90, 0x9d):
                        out.append(ord(ch))
                    else:
                        out.extend(ch.encode(codec))
                except UnicodeEncodeError:
                    if codec != 'cp1252' and not flags & 0x400:
                        raise RuntimeError(f'{name}: best-fit table missing for {codec}') from None
                    out.extend(replacement)
                    used = True
            data = bytes(out)
            result = self._output(dst, cap, data, 1)
            if result and a(7):
                self.m.put32(a(7), int(used))
            return result
        except UnicodeError:
            return self._error(1113)  # ERROR_NO_UNICODE_TRANSLATION

    def _ctype(self, ch):
        category = unicodedata.category(ch)
        return (int(ch.isupper()) | (int(ch.islower()) << 1) | (int(ch.isdecimal()) << 2)
                | (int(ch.isspace()) << 3) | (int(category.startswith('P')) << 4)
                | (int(category == 'Cc') << 5) | (int(category == 'Zs' or ch == '\t') << 6)
                | (int(ch in '0123456789ABCDEFabcdef') << 7) | (int(ch.isalpha()) << 8)
                | (int(category not in ('Cn', 'Cs')) << 9))

    def _tls_address(self, index, create=False):
        if index < 64:
            return self.m.teb + 0x1480 + 8 * index
        ext = self.m.u64(self.m.teb + 0x1780)
        if not ext and create:
            ext = self.m.alloc(8 * 1024)
            self.m.put64(self.m.teb + 0x1780, ext)
        return ext + 8 * (index - 64) if ext else 0

    def _slot(self, name, a):
        tls = name.startswith('Tls')
        slots = self.tls if tls else self.fls
        if name.endswith('Alloc'):
            end = 1088 if tls else 128
            for i in range(0 if tls else 1, end):
                if i not in slots:
                    slots[i] = (0, 0 if tls else a(0))
                    if tls:
                        self.m.put64(self._tls_address(i, True), 0)
                    return i
            return self._error(8, MASK32)
        i = a(0) & MASK32
        if i not in slots:
            return self._error(INVALID_PARAMETER)
        value, callback = slots[i]
        tid = self.m.current_thread
        if not tls:
            value = self.fls_values.get((tid, i), 0)
        if name.endswith('Free'):
            if callback and value:
                raise RuntimeError('FlsFree: non-null guest destructor needs execution')
            if tls:
                self.m.put64(self._tls_address(i), 0)
            del slots[i]
            for key in [key for key in self.fls_values if key[1] == i]:
                del self.fls_values[key]
        elif name.endswith('GetValue'):
            self.m.set_last_error(0)
            if tls:
                address = self._tls_address(i)
                return self.m.u64(address) if address else 0
            return value
        else:
            if not tls:
                self.fls_values[tid, i] = a(1)
            if tls:
                self.m.put64(self._tls_address(i), a(1))
        return 1

    def _critical(self, name, a):
        ptr = a(0)
        m = self.m
        if name.startswith('Initialize'):
            spin = a(1) & MASK32 if name.endswith(('SpinCount', 'Ex')) else 0
            if name.endswith('Ex'):
                require_flags(a(2) & MASK32, 0x01000001, name)  # NO_DEBUG_INFO | FORCE_DEBUG_INFO
            m.write(ptr, struct.pack('<QiiQQQ', 0, -1, 0, 0, 0, spin))
            self.critical.add(ptr)
            return 1 if name.endswith(('SpinCount', 'Ex')) else 0
        if ptr not in self.critical:
            raise RuntimeError(f'{name}: uninitialized critical section {ptr:#x}')
        count = int.from_bytes(m.read(ptr + 12, 4), 'little')
        if name.startswith('Enter'):
            owner = m.u64(ptr + 16)
            if count and owner != self._id(True):
                result = m.defer_thread(lambda: int.from_bytes(m.read(ptr + 12, 4), 'little') == 0, MASK32)
                if result is m.deferred:
                    return result
                count = 0
            count += 1
        elif name.startswith('Leave') and count:
            count -= 1
        elif name.startswith('Delete') and not count:
            self.critical.remove(ptr)
            m.write(ptr, bytes(40))
            return 0
        else:
            raise RuntimeError(f'{name}: invalid critical section ownership')
        m.write(ptr + 8, struct.pack('<iiQ', count - 1, count, self._id(True) if count else 0))
        return 0

    def _srw(self, name, ptr):
        state = self.srw.get(ptr, 0)  # -1 exclusive, >0 shared
        if name == 'AcquireSRWLockExclusive' and not state:
            self.srw_owners[ptr] = self.m.current_thread
            state = -1
        elif name == 'AcquireSRWLockShared' and state >= 0:
            state += 1
        elif name == 'ReleaseSRWLockExclusive' and state == -1:
            state = 0
        elif name == 'ReleaseSRWLockShared' and state > 0:
            state -= 1
        elif name.startswith('Acquire'):
            exclusive = name.endswith('Exclusive')
            result = self.m.defer_thread(lambda: self.srw.get(ptr, 0) == 0 if exclusive
                                         else self.srw.get(ptr, 0) >= 0, MASK32)
            if result is self.m.deferred:
                return result
            return self._srw(name, ptr)
        else:
            raise RuntimeError(f'{name}: invalid ownership')
        if state:
            self.srw[ptr] = state
        else:
            self.srw.pop(ptr, None)
            self.srw_owners.pop(ptr, None)
        self.m.put64(ptr, (state << 4 | 1) if state > 0 else int(state < 0))
        return 0

    def _mutex(self, name, a):
        if name == 'CreateMutexW':
            if a(0):
                raise RuntimeError('CreateMutexW: security attributes not modeled')
            key = self.m.cstr(a(2), wide=True) if a(2) else None
            state = self.named_mutexes.get(key)
            if state is None:
                state = [int(bool(a(1) & MASK32)), key, 0,
                         self.m.current_thread if a(1) & MASK32 else None]
                if key is not None:
                    self.named_mutexes[key] = state
                self.m.set_last_error(0)
            else:
                self.m.set_last_error(183)
            h = self.next_handle
            self.next_handle += 4
            self.mutex_handles[h] = state
            state[2] += 1
            return h
        h = a(0)
        if h not in self.mutex_handles:
            if name == 'CloseHandle' and h in self.console.values():
                self.console = {k: v for k, v in self.console.items() if v != h}
                return 1
            return self._error(6, MASK32 if name == 'WaitForSingleObject' else 0)
        state = self.mutex_handles[h]
        if name == 'WaitForSingleObject':
            tid = self.m.current_thread
            result = self.m.defer_thread(lambda: not state[0] or state[3] == tid,
                                         a(1) & MASK32)
            if result is not self.m.deferred and result == 0:
                state[0] += 1
                state[3] = self.m.current_thread
            return result
        if name == 'ReleaseMutex':
            if not state[0]:
                return self._error(288)
            state[0] -= 1
            if not state[0]:
                state[3] = None
        else:
            del self.mutex_handles[h]
            state[2] -= 1
            if not state[2] and state[1] is not None:
                del self.named_mutexes[state[1]]
        return 1

    def _module_name(self, handle):
        if not handle:
            return str(self.m.target_path)
        mod = self.m.module_for_address(handle)
        if mod is None or mod.base != handle:
            return None
        return str(getattr(mod, 'path', mod.name))

    def _module(self, name, a):
        m = self.m
        wide = name.endswith('W')
        if name == 'GetProcAddress':
            if not a(0) or not a(1):
                return self._error(127)
            proc = a(1) if a(1) <= 0xffff else m.cstr(a(1))
            addr = m.export_address(a(0), proc)
            return addr or self._error(127)
        if name.startswith('GetModuleFileName'):
            path = self._module_name(a(0))
            if path is None:
                return self._error(126)
            unit = 2 if wide else 1
            data = path.encode('utf-16-le' if wide else 'cp1252', 'replace')
            capacity = (a(2) & MASK32) * unit
            if capacity <= len(data):
                if capacity:
                    m.write(a(1), data[:capacity-unit] + bytes(unit))
                return self._error(INSUFFICIENT_BUFFER, capacity // unit)
            m.write(a(1), data + bytes(unit))
            return len(data) // unit
        if name.startswith('GetModuleHandle') and not a(0):
            return m.u64(m.peb + 0x10)
        if not a(0):
            return self._error(126)
        if 'Ex' in name:
            if a(1):
                raise RuntimeError(f'{name}: non-null file handle not modeled')
            require_flags(a(2) & MASK32, 0x800, name)  # LOAD_LIBRARY_SEARCH_SYSTEM32
        lib = m.cstr(a(0), wide=wide)
        if name.startswith('GetModuleHandle'):
            # Look only in the loader's InLoadOrderModuleList, never load on lookup.
            ldr = m.u64(m.peb + 0x18)
            if not ldr:
                return self._error(126)
            head = ldr + 0x10
            link = m.u64(head)
            seen = set()
            norm = lib.replace('/', '\\').lower()
            if '.' not in norm.rsplit('\\', 1)[-1]:
                norm += '.dll'
            while link and link != head and link not in seen:
                seen.add(link)
                field = link + (0x48 if '\\' in norm else 0x58)  # Full/BaseDllName
                n = int.from_bytes(m.read(field, 2), 'little')
                p = m.u64(field + 8)
                if p and m.read(p, n).decode('utf-16-le').replace('/', '\\').lower() == norm:
                    return m.u64(link + 0x30)
                link = m.u64(link)
            return self._error(126)
        try:
            module = m.load_module(lib)
        except FileNotFoundError:
            return self._error(126)
        return module.base

    def _file(self, name, a):
        m = self.m
        if name in ('CreateFileW', 'CreateFileA'):
            access, disposition = a(1) & MASK32, a(4) & MASK32
            if a(6):
                raise RuntimeError(f'{name}: template handles are not modeled')
            text = str(PureWindowsPath(m.cstr(a(0), wide=name.endswith('W')))).lower()
            if text.startswith('c:\\temp\\'):
                if access & ~0xc0000000 or disposition not in (1, 2, 3, 4, 5):
                    raise RuntimeError(f'{name}: unsupported virtual temporary-file mode')
                exists = text in self.temp_files
                if disposition == 1 and exists:
                    return self._error(80, MASK64)
                if disposition in (3, 5) and not exists:
                    return self._error(2, MASK64)
                if disposition in (1, 2, 5) or not exists:
                    self.temp_files[text] = bytearray()
                data = self.temp_files[text]
                writable = bool(access & 0x40000000)
            else:
                if access != 0x80000000 or disposition != 3:
                    raise RuntimeError(f'{name}: only approved PE inputs may be read outside guest temp')
                leaf = PureWindowsPath(text).name
                module = next((item for item in m.modules if item.name == leaf), None)
                if module is None:
                    local = m.target_path.parent / leaf
                    if not local.is_file():
                        return self._error(2, MASK64)
                    raise RuntimeError(f'{name}: existing file not in approved mapped PE inputs: {text}')
                data, writable = module.pe.__data__, False
            h = self.next_handle
            self.next_handle += 4
            self.file_handles[h] = [data, 0, writable]
            return h
        if name in ('DeleteFileW', 'DeleteFileA'):
            text = str(PureWindowsPath(m.cstr(a(0), wide=name.endswith('W')))).lower()
            if text not in self.temp_files:
                return self._error(2)
            del self.temp_files[text]
            return 1
        if name == 'FindFirstFileW':
            text = PureWindowsPath(m.cstr(a(0), wide=True))
            if not (m.target_path.parent / text.parent.name).is_dir():
                return self._error(3, MASK64)
            raise RuntimeError(f'FindFirstFileW: directory enumeration not modeled: {text}')
        if name == 'UnmapViewOfFile':
            if a(0) not in self.file_views:
                return self._error(487)
            del self.file_views[a(0)]
            return int(m.free(a(0)))
        if name == 'MapViewOfFile':
            data = self.mapping_handles.get(a(0))
            if data is None:
                return self._error(6)
            require_flags(a(1) & MASK32, 4, name)
            offset = ((a(2) & MASK32) << 32) | (a(3) & MASK32)
            size = a(4) or len(data) - offset
            if size <= 0 or offset + size > len(data):
                return self._error(87)
            ptr = m.alloc(size)
            m.write(ptr, data[offset:offset + size])
            self.file_views[ptr] = size
            return ptr
        handle = a(0)
        if name == 'CloseHandle':
            if self.file_handles.pop(handle, None) is not None:
                return 1
            return int(self.mapping_handles.pop(handle, None) is not None)
        if handle not in self.file_handles:
            return self._error(6, MASK32 if name in ('GetFileSize', 'SetFilePointer') else 0)
        state = self.file_handles[handle]
        data, pos, writable = state
        if name == 'CreateFileMappingW':
            if (a(2) & MASK32) != 2 or a(3) or a(4) or a(5):
                raise RuntimeError('CreateFileMappingW: only unnamed read-only whole-file mappings')
            h = self.next_handle
            self.next_handle += 4
            self.mapping_handles[h] = data
            return h
        if name in ('GetFileSize', 'GetFileSizeEx'):
            if name.endswith('Ex'):
                m.put64(a(1), len(data))
                return 1
            if a(1):
                m.put32(a(1), len(data) >> 32)
            return len(data) & MASK32
        if name in ('SetFilePointer', 'SetFilePointerEx'):
            if name.endswith('Ex'):
                delta = a(1) - ((a(1) >> 63) << 64)
            elif a(2):
                high = int.from_bytes(m.read(a(2), 4), 'little', signed=True)
                delta = (high << 32) | (a(1) & MASK32)
            else:
                delta = signed32(a(1))
            origin = a(3) & MASK32
            if origin not in (0, 1, 2):
                return self._error(87, 0 if name.endswith('Ex') else MASK32)
            dest = (0, pos, len(data))[origin] + delta
            if dest < 0:
                return self._error(131, 0 if name.endswith('Ex') else MASK32)
            state[1] = dest
            if name.endswith('Ex'):
                if a(2):
                    m.put64(a(2), dest)
                return 1
            if a(2):
                m.put32(a(2), dest >> 32)
            return dest & MASK32
        if name == 'WriteFile':
            if not writable:
                return self._error(5)
            if a(4):
                raise RuntimeError('WriteFile: overlapped I/O is not modeled')
            count = a(2) & MASK32
            if pos + count > 64 * 1024 * 1024:
                raise RuntimeError('Virtual temporary file exceeds 64 MiB')
            if pos + count > len(data):
                data.extend(bytes(pos + count - len(data)))
            data[pos:pos + count] = m.read(a(1), count)
            state[1] += count
            if a(3):
                m.put32(a(3), count)
            return 1
        if name == 'ReadFile':
            if a(4):
                raise RuntimeError('ReadFile: overlapped I/O is not modeled')
            count = min(a(2) & MASK32, max(0, len(data) - pos))
            if count:
                m.write(a(1), data[pos:pos + count])
            state[1] += count
            if a(3):
                m.put32(a(3), count)
            return 1
        return None

    def _version_resource(self, path):
        leaf = PureWindowsPath(path).name.lower()
        module = next((item for item in self.m.modules if item.name == leaf), None)
        if module is None:
            return None
        pe = module.pe
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            pe.parse_data_directories(directories=[2])
        for entry in getattr(getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None), 'entries', []):
            if entry.id == 16:
                item = entry.directory.entries[0].directory.entries[0].data.struct
                return pe.get_data(item.OffsetToData, item.Size)
        return None

    def dispatch(self, name, args):
        """Return the guest API result, or None if this export is not modeled."""
        m, a = self.m, args
        if name in ('ZwTerminateProcess', 'NtTerminateProcess', 'ExitProcess'):
            status = (a(0) if name == 'ExitProcess' else a(1)) & MASK32
            raise RuntimeError(f'Guest requested process termination with status {status:#x}')
        if name in ('ZwRaiseHardError', 'NtRaiseHardError'):
            messages = []
            for i in range(min(a(1), 8)):
                if a(2) & (1 << i):
                    descriptor = m.u64(a(3) + i * 8)
                    length = int.from_bytes(m.read(descriptor, 2), 'little')
                    messages.append(m.read(m.u64(descriptor + 8), length).decode('utf-16-le'))
            raise RuntimeError('Guest hard error: ' + ' | '.join(messages))
        if name == 'CreateTimerQueueTimer':
            if a(1) or a(5) & MASK32:
                raise RuntimeError('CreateTimerQueueTimer: only default-queue one-shot timers modeled')
            require_flags(a(6) & MASK32, 0x20, name)
            tid = m.queue_timer(a(2), a(3), a(4) & MASK32)
            handle = self.next_handle
            self.next_handle += 4
            self.timer_handles[handle] = tid
            m.put64(a(0), handle)
            return 1
        if name == 'DeleteTimerQueueTimer':
            tid = self.timer_handles.get(a(1))
            if a(0) or tid is None:
                return self._error(6)
            thread = m.threads[tid]
            if thread['context'] is not None and thread['exit'] is None:
                if a(2) == MASK64:
                    result = m.defer_thread(lambda: thread['exit'] is not None, MASK32)
                    if result is m.deferred:
                        return result
                else:
                    return self._error(997)
            thread['exit'] = 0
            m.timers.pop(tid, None)
            del self.timer_handles[a(1)]
            return 1
        if name in ('GlobalAddAtomW', 'GlobalFindAtomW'):
            if a(0) <= 0xffff:
                return a(0)
            text = m.cstr(a(0), wide=True).casefold()
            if text not in self.atoms:
                if name == 'GlobalFindAtomW':
                    return self._error(2)
                if self.next_atom >= 0xffff:
                    return self._error(8)
                self.atoms[text] = [self.next_atom, 0]
                self.next_atom += 1
            if name == 'GlobalAddAtomW':
                self.atoms[text][1] += 1
            return self.atoms[text][0]
        if name == 'GlobalDeleteAtom':
            for key, state in self.atoms.items():
                if state[0] == a(0):
                    state[1] -= 1
                    if not state[1]:
                        del self.atoms[key]
                    return 0
            return self._error(6, a(0))
        if name == 'CreateToolhelp32Snapshot':
            if a(0) & MASK32 != 2 or a(1):
                raise RuntimeError('CreateToolhelp32Snapshot: only guest process enumeration modeled')
            handle = self.next_handle
            self.next_handle += 4
            self.snapshots[handle] = False
            return handle
        if name in ('Process32FirstW', 'Process32NextW', 'Process32First', 'Process32Next'):
            if a(0) not in self.snapshots:
                return self._error(6)
            if 'Next' in name and self.snapshots[a(0)]:
                return self._error(18)
            wide = name.endswith('W')
            size = 568 if wide else 304
            if int.from_bytes(m.read(a(1), 4), 'little') != size:
                return self._error(24)
            data = bytearray(size)
            struct.pack_into('<III4xQIIIiI', data, 0, size, 0, self._id(), 0, 0,
                             len(m.threads), 0, 8, 0)
            filename = m.target_path.name.encode('utf-16-le' if wide else 'cp1252')
            data[44:44 + len(filename)] = filename
            m.write(a(1), bytes(data))
            self.snapshots[a(0)] = True
            return 1
        if name == 'CloseHandle' and a(0) in self.snapshots:
            del self.snapshots[a(0)]
            return 1
        if name == 'CoCreateInstance':
            m.put64(a(4), 0)
            return 0x80040154  # REGDB_E_CLASSNOTREG: the guest COM registry is empty.
        if name == 'CoInitializeEx':
            if a(0):
                return 0x80070057
            mode = a(1) & MASK32
            require_flags(mode, 0xe, name)
            apartment = mode & 2
            old = self.com_apartments.get(m.current_thread)
            if old and old[0] != apartment:
                return 0x80010106
            self.com_apartments[m.current_thread] = (apartment, old[1] + 1 if old else 1)
            return 1 if old else 0
        if name == 'CoUninitialize':
            old = self.com_apartments.get(m.current_thread)
            if old:
                if old[1] == 1:
                    del self.com_apartments[m.current_thread]
                else:
                    self.com_apartments[m.current_thread] = (old[0], old[1] - 1)
            return 0
        if name == 'CreateThread':
            if a(0):
                raise RuntimeError('CreateThread: security attributes not modeled')
            flags = a(4) & MASK32
            require_flags(flags, 0x10004, name)
            tid = m.create_thread(a(2), a(3), a(1), bool(flags & 4))
            handle = self.next_handle
            self.next_handle += 4
            self.thread_handles[handle] = tid
            if a(5):
                m.put32(a(5), tid)
            return handle
        if name in ('ResumeThread', 'GetExitCodeThread'):
            tid = self.thread_handles.get(a(0))
            if tid is None:
                return self._error(6, MASK32 if name == 'ResumeThread' else 0)
            thread = m.threads[tid]
            if name == 'ResumeThread':
                old = int(thread['suspended'])
                thread['suspended'] = False
                return old
            m.put32(a(1), 259 if thread['exit'] is None else thread['exit'])
            return 1
        if name in ('Sleep', 'SleepEx'):
            if name == 'SleepEx' and a(1):
                raise RuntimeError('SleepEx: alertable callbacks not modeled')
            return m.sleep_thread(a(0) & MASK32)
        if name in ('CreateEventW', 'CreateEventA'):
            if a(0) or a(3):
                raise RuntimeError('CreateEvent: only unnamed guest events are modeled')
            handle = self.next_handle
            self.next_handle += 4
            self.kernel_events[handle] = [bool(a(1)), bool(a(2))]
            return handle
        if name in ('SetEvent', 'ResetEvent'):
            state = self.kernel_events.get(a(0))
            if state is None:
                return self._error(6)
            state[1] = name == 'SetEvent'
            return 1
        if name == 'WaitForSingleObject' and a(0) in self.thread_handles:
            tid = self.thread_handles[a(0)]
            return m.defer_thread(lambda: m.threads[tid]['exit'] is not None, a(1) & MASK32)
        if name == 'WaitForSingleObject' and a(0) in self.kernel_events:
            state = self.kernel_events[a(0)]
            result = m.defer_thread(lambda: state[1], a(1) & MASK32)
            if result == 0 and not state[0]:
                state[1] = False
            return result
        if name == 'CloseHandle' and a(0) in self.thread_handles:
            del self.thread_handles[a(0)]
            return 1
        if name == 'CloseHandle' and a(0) in self.kernel_events:
            del self.kernel_events[a(0)]
            return 1
        if name == 'CloseHandle' and a(0) in self.token_handles:
            del self.token_handles[a(0)]
            return 1
        if name in ('ntohl', 'htonl', 'ntohs', 'htons'):
            size = 2 if name.endswith('s') else 4
            return int.from_bytes((a(0) & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'), 'big')
        if name == 'IsBadReadPtr':
            address, end = a(0), a(0) + a(1)
            if end > MASK64:
                return 1
            for lo, hi, protection in sorted(m.uc.mem_regions()):
                if hi < address:
                    continue
                if lo > address or not protection & 1:
                    return 1
                address = hi + 1
                if address >= end:
                    return 0
            return int(a(1) != 0)
        if name == 'GetFileVersionInfoSizeW':
            data = self._version_resource(m.cstr(a(0), wide=True))
            if a(1):
                m.put32(a(1), 0)
            return len(data) if data else self._error(1813)
        if name == 'GetFileVersionInfoW':
            data = self._version_resource(m.cstr(a(0), wide=True))
            if data is None or a(2) < len(data):
                return self._error(122)
            m.write(a(3), data)
            return 1
        if name == 'VerQueryValueW':
            query = m.cstr(a(1), wide=True)
            if query != '\\':
                raise RuntimeError(f'VerQueryValueW: unsupported subblock {query}')
            length = int.from_bytes(m.read(a(0) + 2, 2), 'little')
            key = m.cstr(a(0) + 6, wide=True)
            offset = (6 + (len(key) + 1) * 2 + 3) & ~3
            m.put64(a(2), a(0) + offset)
            m.put32(a(3), length)
            return 1
        if name == 'GetFileAttributesW':
            text = PureWindowsPath(m.cstr(a(0), wide=True))
            module = next((item for item in m.modules if item.name == text.name.lower()), None)
            if module is not None:
                return 0x20
            local = m.target_path.parent / text.name
            if local.is_dir():
                return 0x10
            if local.is_file():
                return 0x20
            return self._error(2, MASK32)
        if name == 'LookupPrivilegeValueW':
            if a(0):
                return self._error(1722)
            privilege = m.cstr(a(1), wide=True)
            identifiers = {'SeDebugPrivilege': 20, 'SeLoadDriverPrivilege': 10,
                           'SeIncreaseBasePriorityPrivilege': 14, 'SeProfileSingleProcessPrivilege': 13}
            if privilege not in identifiers:
                return self._error(1313)
            m.put64(a(2), identifiers[privilege])
            return 1
        if name == 'OpenProcessToken':
            if a(0) != MASK64:
                return self._error(6)
            handle = self.next_handle
            self.next_handle += 4
            self.token_handles[handle] = a(1) & MASK32
            m.put64(a(2), handle)
            return 1
        if name == 'GetTokenInformation':
            access = self.token_handles.get(a(0))
            if access is None or not access & 8:
                return self._error(6 if access is None else 5)
            kind = a(1) & MASK32
            values = {8: 1, 18: 1, 20: 0, 21: 0, 24: 0, 26: 0}
            if kind not in values:
                raise RuntimeError(f'GetTokenInformation: class not modeled: {kind}')
            m.put32(a(4), 4)
            if a(3) < 4:
                return self._error(122)
            m.put32(a(2), values[kind])
            return 1
        if name == 'AdjustTokenPrivileges':
            access = self.token_handles.get(a(0))
            if access is None:
                return self._error(6)
            if not access & 0x20:
                return self._error(5)
            count = 0 if a(1) else int.from_bytes(m.read(a(2), 4), 'little')
            if a(4):
                if a(3) < 4:
                    if a(5):
                        m.put32(a(5), 4)
                    return self._error(122)
                m.put32(a(4), 0)
            if a(5):
                m.put32(a(5), 4)
            # The guest standard-user token has no requested elevated privileges.
            m.set_last_error(1300 if count else 0)
            return 1
        if name == 'IsWow64Process2':
            if a(0) != MASK64:
                return self._error(6)
            m.write(a(1), struct.pack('<H', 0))
            m.write(a(2), struct.pack('<H', 0x8664))
            return 1
        if name in ('CreateFileW', 'CreateFileA', 'ReadFile', 'WriteFile',
                    'FindFirstFileW',
                    'DeleteFileW', 'DeleteFileA', 'GetFileSize', 'GetFileSizeEx',
                    'SetFilePointer', 'SetFilePointerEx', 'CreateFileMappingW',
                    'MapViewOfFile', 'UnmapViewOfFile'):
            return self._file(name, a)
        if name == 'CloseHandle' and (a(0) in self.file_handles or a(0) in self.mapping_handles):
            return self._file(name, a)
        if name.startswith('Zw'):
            name = 'Nt' + name[2:]
        if name in ('NtOpenFile', 'NtCreateFile'):
            attrs = a(2)
            descriptor = m.u64(attrs + 16)
            text = m.cstr(m.u64(descriptor + 8), wide=True)
            leaf = PureWindowsPath(text).name.lower()
            if any(module.name == leaf for module in m.modules):
                raise RuntimeError(f'{name}: existing PE requires native file handle model: {text}')
            status = 0xc0000034  # STATUS_OBJECT_NAME_NOT_FOUND in the guest namespace.
            m.put64(a(0), 0)
            m.write(a(3), struct.pack('<QQ', status, 0))
            return status
        if name == 'NtSetInformationThread':
            if a(1) & MASK32 != 0x11:
                raise RuntimeError('NtSetInformationThread: only ThreadHideFromDebugger modeled')
            if a(3):
                return 0xc0000004
            if a(0) != MASK64 - 1:
                return STATUS_INVALID_HANDLE
            self.hidden_threads.add(m.current_thread)
            return 0
        if name == 'NtQueryInformationThread':
            if a(0) != MASK64 - 1:
                return STATUS_INVALID_HANDLE
            if a(1) & MASK32 != 0x11:
                raise RuntimeError('NtQueryInformationThread: only ThreadHideFromDebugger modeled')
            if a(4):
                try:
                    value = m.read(a(4), 4)
                    m.write(a(4), value)
                except UcError:
                    return 0xc0000005
            if a(3) != 1:
                return 0xc0000004
            m.write(a(2), bytes((int(m.current_thread in self.hidden_threads),)))
            if a(4):
                m.put32(a(4), 1)
            return 0
        if name == 'NtSetContextThread':
            if a(0) != MASK64 - 1:
                return STATUS_INVALID_HANDLE
            flags = int.from_bytes(m.read(a(1) + 0x30, 4), 'little')
            if flags != 0x100010:
                raise RuntimeError(f'NtSetContextThread: unsupported CONTEXT flags {flags:#x}')
            self.thread_debug_registers[m.current_thread] = tuple(m.u64(a(1) + offset) for offset in (0x48, 0x50, 0x58, 0x60, 0x68, 0x70))
            return 0
        if name == 'NtOpenProcess':
            if m.u64(a(3)) != self._id() or m.u64(a(3) + 8):
                return STATUS_INVALID_PARAMETER
            require_flags(a(1) & MASK32, 0x410, name)
            m.put64(a(0), MASK64)
            return 0
        if name == 'NtClose' and a(0) == MASK64:
            return 0
        if name == 'NtQueryInformationProcess':
            if a(0) != MASK64:
                return STATUS_INVALID_HANDLE
            if a(1) & MASK32 != 0:
                raise RuntimeError('NtQueryInformationProcess: only ProcessBasicInformation modeled')
            if a(3) < 48:
                if a(4):
                    m.put32(a(4), 48)
                return 0xc0000004
            m.write(a(2), struct.pack('<QQQi4xQQ', 0x103, m.peb, 1, 8, self._id(), 0))
            if a(4):
                m.put32(a(4), 48)
            return 0
        if name in ('NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'NtFreeVirtualMemory'):
            return self._virtual(name[2:-len('VirtualMemory')], a)
        if name == 'VirtualProtect':
            if not a(3):
                return self._error(998)
            status, old = self._protect(a(0), a(1), a(2) & MASK32)
            if status:
                return self._error(487 if status == STATUS_MEMORY_NOT_ALLOCATED else INVALID_PARAMETER)
            m.put32(a(3), old)
            return 1
        if name in ('GetProcessHeap', 'RtlGetProcessHeap'):
            return self._heap()
        if name == 'HeapCreate':
            require_flags(a(0) & MASK32, 0x40001, name)
            if a(2):
                raise RuntimeError('HeapCreate: fixed maximum heaps not modeled')
            handle = m.alloc(PAGE)
            self.private_heaps.add(handle)
            return handle
        if name == 'HeapDestroy':
            handle = a(0)
            if handle not in self.private_heaps:
                return self._error(6)
            for ptr, owner in list(self.heap_owners.items()):
                if owner == handle:
                    self._heap_free(ptr)
                    del self.heap_owners[ptr]
            self.private_heaps.remove(handle)
            return int(m.free(handle))
        heap_op = {'HeapAlloc': 'Alloc', 'RtlAllocateHeap': 'Alloc', 'HeapReAlloc': 'ReAlloc',
                   'RtlReAllocateHeap': 'ReAlloc', 'HeapSize': 'Size', 'RtlSizeHeap': 'Size',
                   'HeapFree': 'Free', 'RtlFreeHeap': 'Free'}.get(name)
        if heap_op:
            return self._heap_call(heap_op, a)
        if name in ('getaddrinfo', 'GetAddrInfoW'):
            m.put64(a(3), 0)
            self.wsa_error = 11001  # WSAHOST_NOT_FOUND in the networkless guest.
            return self.wsa_error
        if name == 'WSACleanup':
            return 0
        if name == 'closesocket':
            self.wsa_error = 10038  # WSAENOTSOCK; no socket was created.
            return MASK32
        if name == 'socket':
            self.wsa_error = 10050  # WSAENETDOWN: the guest has no network devices.
            return MASK64
        if name == 'WSAGetLastError':
            return getattr(self, 'wsa_error', 0)
        if name == 'WSASetLastError':
            self.wsa_error = a(0) & MASK32
            return 0
        if name == 'WSACreateEvent':
            handle = self.next_handle
            self.next_handle += 4
            self.events[handle] = False
            return handle
        if name in ('WSASetEvent', 'WSAResetEvent', 'WSACloseEvent'):
            if a(0) not in self.events:
                return self._error(6)
            if name == 'WSACloseEvent':
                del self.events[a(0)]
            else:
                self.events[a(0)] = name == 'WSASetEvent'
            return 1
        if name == 'WSAWaitForMultipleEvents':
            count = a(0) & MASK32
            if not 1 <= count <= 64 or a(4):
                raise RuntimeError('WSAWaitForMultipleEvents: unsupported event count or alertable wait')
            handles = [m.u64(a(1) + i * 8) for i in range(count)]
            if any(handle not in self.events for handle in handles):
                return MASK32
            ready = [self.events[handle] for handle in handles]
            if a(2):
                if all(ready):
                    return 0
            elif any(ready):
                return ready.index(True)
            predicate = (lambda: all(self.events[handle] for handle in handles)) if a(2) else (
                         lambda: any(self.events[handle] for handle in handles))
            result = m.defer_thread(predicate, a(3) & MASK32)
            if result == 0 and not a(2):
                return next(i for i, handle in enumerate(handles) if self.events[handle])
            return result
        if name == 'WSAStartup':
            if a(0) & 0xffff != 0x0202:
                return 10092
            data = bytearray(408)
            struct.pack_into('<HH', data, 0, 0x0202, 0x0202)
            data[16:33] = b'Isolated emulator'
            data[273:295] = b'No external networking'
            m.write(a(1), bytes(data))
            return 0
        if name == 'VerSetConditionMask':
            mask, fields, condition = a(0), a(1) & MASK32, a(2) & 7
            for i in range(8):
                if fields & (1 << i):
                    mask = (mask & ~(7 << (i * 3))) | (condition << (i * 3))
            return mask
        if name in ('RtlVerifyVersionInfo', 'VerifyVersionInfoW'):
            data = m.read(a(0), 284)
            _, major, minor, build, platform = struct.unpack_from('<5I', data)
            spmajor, spminor, suite, product, _ = struct.unpack_from('<HHHBB', data, 276)
            requested = (minor, major, build, platform, spminor, spmajor, suite, product)
            current = (0, 10, 19044, 2, 0, 0, 0x100, 1)
            fields, conditions = a(1) & MASK32, a(2)
            version_fields = [i for i in (1, 0, 5, 4) if fields & (1 << i)]
            ok = True
            for i in (3, 2, 6, 7, *version_fields):
                if not fields & (1 << i):
                    continue
                actual, wanted = current[i], requested[i]
                condition = (conditions >> (3 * i)) & 7
                comparisons = {1: actual == wanted, 2: actual > wanted,
                               3: actual >= wanted, 4: actual < wanted,
                               5: actual <= wanted, 6: actual & wanted == wanted,
                               7: bool(actual & wanted)}
                if condition not in comparisons:
                    return 0xc000000d if name.startswith('Rtl') else self._error(87)
                if not comparisons[condition]:
                    ok = False
                    break
                if i in version_fields and actual != wanted:
                    break
            return (0 if ok else 0xc0000059) if name.startswith('Rtl') else (1 if ok else self._error(1150))
        if name == 'GetModuleHandleExW':
            flags = a(0) & MASK32
            require_flags(flags, 7, name)
            if not flags & 4:
                raise RuntimeError('GetModuleHandleExW: only FROM_ADDRESS is modeled')
            module = m.module_for_address(a(1))
            if module is None:
                return self._error(126)
            m.put64(a(2), module.base)
            return 1
        if name in ('GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
                    'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleFileNameA', 'GetModuleFileNameW'):
            return self._module(name, a)
        if name == 'GetLastError':
            return m.get_last_error()
        if name == 'SetLastError':
            m.set_last_error(a(0) & MASK32)
            return 0
        if name in ('GetCurrentThreadId', 'GetCurrentProcessId'):
            return self._id(name == 'GetCurrentThreadId')
        if name in ('GetCurrentThread', 'GetCurrentProcess'):
            return MASK64 - int(name == 'GetCurrentThread')
        if name in ('RtlGetVersion', 'GetVersionExW'):
            size = int.from_bytes(m.read(a(0), 4), 'little')
            if size not in (276, 284):
                return STATUS_INVALID_PARAMETER if name.startswith('Rtl') else self._error(87)
            data = bytearray(size)
            struct.pack_into('<5I', data, 0, size, 10, 0, 19044, 2)
            if size == 284:
                struct.pack_into('<HHHBB', data, 276, 0, 0, 0x100, 1, 0)
            m.write(a(0), bytes(data))
            return 0 if name.startswith('Rtl') else 1
        if name in ('GetSystemInfo', 'GetNativeSystemInfo'):
            m.write(a(0), struct.pack('<HHIQQQIIIHH', 9, 0, PAGE,
                    0x10000, 0x7ffffffeffff, 1, 1, 8664, 0x10000, 6, 0x9e0a))
            return 0
        if name in ('GetSystemTimeAsFileTime', 'GetSystemTimePreciseAsFileTime'):
            m.put64(a(0), FILETIME_EPOCH + self._clock())
            return 0
        if name in ('QueryPerformanceCounter', 'QueryPerformanceFrequency'):
            m.put64(a(0), self._clock() if name.endswith('Counter') else 10000000)
            return 1
        if name in ('GetTickCount', 'GetTickCount64'):
            return (self._clock() // 10000) & (MASK64 if name.endswith('64') else MASK32)
        if name == 'GetThreadTimes':
            if a(0) != MASK64 - 1:
                return self._error(6)
            # Running thread has not exited. Model all elapsed execution as user time.
            for i, val in enumerate((FILETIME_EPOCH, 0, 0, self._clock()), 1):
                m.put64(a(i), val)
            return 1
        if name == 'GetVersion':
            return (19044 << 16) | 10
        if name == 'GetUserDefaultUILanguage':
            return 0x0409  # The guest locale is en-US.
        if name == 'GetLocaleInfoEx':
            locale = m.cstr(a(0), wide=True).lower() if a(0) else 'en-us'
            if locale not in ('', 'en-us'):
                raise RuntimeError(f'GetLocaleInfoEx: locale not modeled: {locale}')
            values = {0x22: '0', 0x23: '1', 0x25: '0', 0x1009: '0',
                      0x0e: '.', 0x0f: ',', 0x1d: '/', 0x1e: ':',
                      0x1f: 'M/d/yyyy', 0x20: 'dddd, MMMM d, yyyy',
                      0x1003: 'h:mm:ss tt', 0x28: 'AM', 0x29: 'PM'}
            kind = a(1) & MASK32
            if kind not in values:
                raise RuntimeError(f'GetLocaleInfoEx: LCType not modeled: {kind:#x}')
            return self._output(a(2), signed32(a(3)), (values[kind] + '\0').encode('utf-16-le'), 2)
        if name in ('GetTempPathA', 'GetTempPathW'):
            text = 'C:\\Temp\\'
            if (a(0) & MASK32) <= len(text):
                return len(text) + 1
            m.write(a(1), (text + '\0').encode('utf-16-le' if name.endswith('W') else 'cp1252'))
            return len(text)
        if name in ('GetSystemDirectoryW', 'GetSystemDirectoryA'):
            text = str(m.system_dir)
            if (a(1) & MASK32) <= len(text):
                return len(text) + 1
            m.write(a(0), (text + '\0').encode('utf-16-le' if name.endswith('W') else 'cp1252'))
            return len(text)
        if name in ('GetCommandLineW', 'GetCommandLineA'):
            pp = m.u64(m.peb + 0x20)
            cmd = m.u64(pp + 0x78) if pp else 0
            if name.endswith('W') and cmd:
                return cmd
            text = m.cstr(cmd, wide=True) if cmd else f'"{m.target_path}"'
            return self._buffer(name, (text + '\0').encode('utf-16-le' if name.endswith('W') else 'cp1252', 'replace'))
        if name == 'GetStartupInfoW':
            data = bytearray(104)
            struct.pack_into('<I', data, 0, len(data))
            struct.pack_into('<I', data, 60, 0x100)  # STARTF_USESTDHANDLES
            struct.pack_into('<QQQ', data, 80, *(self.console.get(k, 0) for k in (-10, -11, -12)))
            m.write(a(0), bytes(data))
            return 0
        if name == 'GetEnvironmentStringsW':
            ptr = m.alloc(4)
            self.buffers['env', ptr] = ptr
            return ptr
        if name == 'FreeEnvironmentStringsW':
            if not self.buffers.pop(('env', a(0)), None):
                return self._error(INVALID_PARAMETER)
            return int(m.free(a(0)))
        if name in ('GetEnvironmentVariableW', 'GetEnvironmentVariableA'):
            return self._error(203 if a(0) else INVALID_PARAMETER)
        if name in ('RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW'):
            return 5  # ERROR_ACCESS_DENIED: no writable host registry is exposed.
        if name in ('RegOpenKeyExW', 'RegOpenKeyExA', 'RegOpenKeyW', 'RegOpenKeyA'):
            # This isolated guest has an empty registry; never inspect host keys.
            return 2  # ERROR_FILE_NOT_FOUND
        if name == 'OpenFileMappingW':
            # No externally created shared objects exist in this isolated guest.
            return self._error(2)
        if name == 'AreFileApisANSI':
            return 1
        if name in ('TlsAlloc', 'TlsGetValue', 'TlsSetValue', 'TlsFree', 'FlsAlloc', 'FlsGetValue', 'FlsSetValue', 'FlsFree'):
            return self._slot(name, a)
        short = name.removeprefix('Rtl')
        if short in ('InitializeCriticalSection', 'InitializeCriticalSectionAndSpinCount', 'InitializeCriticalSectionEx',
                     'EnterCriticalSection', 'LeaveCriticalSection', 'DeleteCriticalSection'):
            result = self._critical(short, a)
            return result if result is m.deferred else (0 if name.startswith('Rtl') else result)
        if short in ('InitializeSListHead', 'InitializeSRWLock', 'RunOnceInitialize'):
            m.write(a(0), bytes(16 if short == 'InitializeSListHead' else 8))
            if short == 'InitializeSRWLock':
                self.srw.pop(a(0), None)
            return 0
        if short in ('AcquireSRWLockExclusive', 'AcquireSRWLockShared', 'ReleaseSRWLockExclusive', 'ReleaseSRWLockShared'):
            return self._srw(short, a(0))
        if short in ('EncodePointer', 'DecodePointer'):
            return a(0) ^ 0xc5ac136ea83c57d1
        if name == 'GetStdHandle':
            k = signed32(a(0))
            return self.console[k] if k in self.console else self._error(6, MASK64)
        if name == 'GetFileType':
            return 2 if a(0) in self.console.values() else self._error(6)
        if name == 'GetConsoleMode':
            if a(0) not in self.console.values():
                return self._error(6)
            m.put32(a(1), 0x1f7 if a(0) == self.console.get(-10) else 3)
            return 1
        if name == 'GetACP':
            return 1252
        if name == 'IsValidCodePage':
            cp = a(0) & MASK32
            if cp in CODEPAGES:
                return 1
            if cp in (0, 1, 2, 3, MASK32):
                return 0
            raise RuntimeError(f'IsValidCodePage: unknown guest code page {cp}')
        if name == 'GetCPInfo':
            page = self._page(a(0) & MASK32)
            if not page or not a(1):
                return self._error(INVALID_PARAMETER)
            m.write(a(1), struct.pack('<I2s12s2x', page[1], b'?', page[2]))
            return 1
        if name in ('WideCharToMultiByte', 'MultiByteToWideChar'):
            return self._convert(name, a)
        if name == 'GetStringTypeW':
            length = signed32(a(2))
            if a(0) & MASK32 != 1:
                raise RuntimeError('GetStringTypeW: only CT_CTYPE1 modeled')
            if not a(1) or not a(3) or length == 0 or length < -1:
                return self._error(INVALID_PARAMETER)
            data = self._text(a(1), length, True).encode('utf-16-le', 'surrogatepass')
            out = bytearray(len(data))
            for i, (code,) in enumerate(struct.iter_unpack('<H', data)):
                struct.pack_into('<H', out, 2*i, self._ctype(chr(code)))
            m.write(a(3), bytes(out))
            return 1
        if name == 'LCMapStringEx':
            locale = m.cstr(a(0), wide=True).lower() if a(0) else 'en-us'
            flags, length = a(1) & MASK32, signed32(a(3))
            if locale not in ('', 'en-us') or flags not in (0x100, 0x200) or any(a(i) for i in (6, 7, 8)):
                raise RuntimeError('LCMapStringEx: unsupported locale, flags or extended arguments')
            if not a(2) or length == 0 or length < -1:
                return self._error(INVALID_PARAMETER)
            text = self._text(a(2), length, True)
            data = (text.lower() if flags == 0x100 else text.upper()).encode('utf-16-le', 'surrogatepass')
            return self._output(a(4), signed32(a(5)), data, 2)
        if name == 'RtlPcToFileHeader':
            mod = m.module_for_address(a(0))
            base = mod.base if mod else 0
            m.put64(a(1), base)
            return base
        if name in ('CreateMutexW', 'WaitForSingleObject', 'ReleaseMutex', 'CloseHandle'):
            return self._mutex(name, a)
        if name == 'SetThreadStackGuarantee':
            requested = int.from_bytes(m.read(a(0), 4), 'little')
            if requested:
                top = m.u64(m.teb + 0x08)
                bottom = m.u64(m.teb + 0x1478) or m.u64(m.teb + 0x10)
                if page_up(requested) >= top - bottom:
                    return self._error(8)
            m.put32(a(0), self.stack_guarantee)
            self.stack_guarantee = max(self.stack_guarantee, page_up(requested))
            return 1
        return None
