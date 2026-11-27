"""Emulate the Infinity Nikki x64 loader without executing host PE code.

Install: python -m pip install pefile==2024.8.26 unicorn==2.1.4
Usage: python unpack_exe.py GAME.exe --output dump --system-dir WINDOWS/System32

The adjacent ShippingBase.dll is required. System DLLs are read as PE data,
never loaded into the Python process. On Linux, supply an exported Windows
System32 directory containing ntdll.dll, kernel32.dll, KernelBase.dll and
apisetschema.dll. No Wine, game process, network or driver loading is used.

Outputs are RVA-layout analysis dumps, not rebuilt/runnable executables. A
partial dump has a nonzero exit status and must not be used as an unpacked
baseline. Reaching rewritten original code is a heuristic, not proof that
all runtime-decrypted functions have been recovered.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

import pefile
import unicorn
from unicorn import x86_const as x86

from unpack_winapi import Win64Api
from unpack_seh import Win64Seh

PAGE = 0x1000
MASK64 = (1 << 64) - 1
ARG_REGS = (x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX,
            x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)


def align(value: int, alignment: int = PAGE) -> int:
    return (value + alignment - 1) & -alignment


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Module:
    path: Path
    name: str
    pe: pefile.PE
    base: int
    size: int
    system: bool = False


class Emulator:
    teb = 0x10000000
    peb = teb + 0x2000
    stack = 0x20000000
    stack_size = 0x800000
    sentinel = teb + 0x1F000
    env_size = 0x20000

    def __init__(self, target: Path, system_dir: Path, memory_limit: int, trace_blocks: bool = False):
        self.target_path = target.resolve(strict=True)
        self.system_dir = system_dir.resolve(strict=True)
        self.memory_limit = memory_limit
        self.mapped_bytes = 0
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.modules: list[Module] = []
        self.exports: dict[int, str] = {}
        self.module_aliases: dict[str, str] = {}
        self.allocations: dict[int, tuple[int, int]] = {}
        self.free_regions: list[tuple[int, int]] = []
        self.next_allocation = 0x30000000
        self.next_system_base = 0x7FFB00000000
        self.time_counter = 0
        self.stage = "mapping"
        self.error: str | None = None
        self.oep: int | None = None
        self.pending_exception: tuple[int, int, int] | None = None
        self.seh = Win64Seh(self)
        self.dirty_pages: set[int] = set()
        self.recent_blocks: deque[int] = deque(maxlen=24)
        self.api_counts: Counter[str] = Counter()
        self.api_total = 0
        self.trace_blocks = trace_blocks
        self.api = Win64Api(self)
        self.deferred = object()
        self.current_thread = 1001
        self.threads: dict[int, dict] = {}
        self.next_thread = 1002
        self.thread_yield = False
        self.timers: dict[int, int] = {}
        self.target = self.map_module(self.target_path)
        self.original_code = next(
            section for section in self.target.pe.sections
            if section.Characteristics & 0x20000000
        )
        for name in ("ntdll.dll", "kernel32.dll", "kernelbase.dll"):
            self.load_module(name)
        imports = getattr(self.target.pe, "DIRECTORY_ENTRY_IMPORT", [])
        base_imports = [entry for entry in imports
                        if entry.dll.decode().lower().endswith("shippingbase.dll")]
        if len(base_imports) != 1:
            raise ValueError("Expected one ShippingBase.dll import in the target")
        base_name = base_imports[0].dll.decode()
        self.loader = self.map_module(self.find_file(self.target_path.parent, base_name))
        self.api_sets = self.read_api_sets()
        self.map_region(self.teb, self.env_size)
        self.map_region(self.stack, self.stack_size)
        self.map_region(0x7ffe0000, PAGE)
        self.build_environment()
        self.setup_imports(self.loader)
        self.setup_imports(self.target)
        self.setup_tls()
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self.on_invalid_memory)
        self.uc.hook_add(unicorn.UC_HOOK_INSN, self.on_syscall,
                         None, 1, 0, x86.UC_X86_INS_SYSCALL)
        self.uc.hook_add(unicorn.UC_HOOK_INTR, self.on_interrupt)
        if self.trace_blocks:
            self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self.on_block)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.on_target_write,
                         begin=self.target.base,
                         end=self.target.base + self.target.size - 1)
        self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self.on_original_code,
                         begin=self.target.base + self.original_code.VirtualAddress,
                         end=self.target.base + self.original_code.VirtualAddress
                         + self.original_code.Misc_VirtualSize - 1)

    @staticmethod
    def find_file(directory: Path, name: str) -> Path:
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
        for path in directory.iterdir():
            if path.name.lower() == name.lower() and path.is_file():
                return path
        raise FileNotFoundError(f"Required PE dependency not found: {directory / name}")

    def map_region(self, address: int, size: int) -> None:
        if size <= 0 or self.mapped_bytes + size > self.memory_limit:
            raise RuntimeError("Guest memory limit exceeded")
        self.uc.mem_map(address, size)
        self.mapped_bytes += size

    def map_module(self, path: Path, system: bool = False) -> Module:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[0, 1, 9])
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError(f"Expected an x64 PE32+ image: {path}")
        size = align(pe.OPTIONAL_HEADER.SizeOfImage)
        base = pe.OPTIONAL_HEADER.ImageBase
        if system:
            base = self.next_system_base
            self.next_system_base -= 0x100000000
        self.map_region(base, size)
        self.write(base, pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for section in pe.sections:
            if section.VirtualAddress + section.SizeOfRawData > size:
                raise ValueError(f"Section exceeds SizeOfImage: {path}")
            if section.SizeOfRawData:
                self.write(base + section.VirtualAddress, section.get_data())
        # Keep the guest image header consistent with its mapped address.
        self.put64(base + pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase"), base)
        module = Module(path, path.name.lower(), pe, base, size, system)
        self.modules.append(module)
        if system:
            for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
                if not symbol.forwarder:
                    name = symbol.name.decode() if symbol.name else f"ordinal_{symbol.ordinal}"
                    self.exports[base + symbol.address] = name
            self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self.on_system_code,
                             begin=base, end=base + size - 1)
        return module

    def read_api_sets(self) -> dict[str, list[str]]:
        path = self.find_file(self.system_dir, "apisetschema.dll")
        pe = pefile.PE(str(path), fast_load=True)
        try:
            blob = next(section.get_data() for section in pe.sections
                        if section.Name.startswith(b".apiset"))
            self.api_set_blob = blob
            version, _, _, count, entry_offset, _, _ = struct.unpack_from("<7I", blob)
            if version != 6:
                raise ValueError(f"Unsupported API Set namespace version: {version}")
            result = {}
            for i in range(count):
                _, name_offset, name_length, _, value_offset, value_count = struct.unpack_from(
                    "<6I", blob, entry_offset + i * 24)
                name = blob[name_offset:name_offset + name_length].decode("utf-16le")
                hosts = []
                for j in range(value_count):
                    _, _, _, offset, length = struct.unpack_from("<5I", blob, value_offset + j * 20)
                    host = blob[offset:offset + length].decode("utf-16le")
                    if host:
                        hosts.append(host.lower())
                result[name.lower()] = hosts
            return result
        finally:
            pe.close()

    def load_module(self, name: str) -> Module:
        name = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if not name.endswith((".dll", ".exe")):
            name += ".dll"
        if name.startswith(("api-ms-", "ext-ms-")):
            contract = name.removesuffix(".dll")
            candidates = self.api_sets.get(contract, [])
            if not candidates:
                # Windows resolves compatible minor revisions of API Set contracts.
                family = contract.rsplit("-", 1)[0]
                candidates = next((hosts for key, hosts in self.api_sets.items()
                                   if key.rsplit("-", 1)[0] == family), [])
            if not candidates:
                raise RuntimeError(f"Unresolved API Set contract: {name}")
            self.module_aliases[name] = candidates[0]
            name = candidates[0]
        for module in self.modules:
            if module.name == name:
                return module
        # Never load additional game/anti-cheat modules on demand.
        module = self.map_module(self.find_file(self.system_dir, name), system=True)
        if hasattr(self, "ldr"):
            self.build_module_list()
        return module

    def export_address(self, module_base: int, name: str | int, depth: int = 0) -> int:
        if depth > 16:
            raise RuntimeError("Forwarded export recursion limit exceeded")
        module = next((item for item in self.modules if item.base == module_base), None)
        if module is None:
            return 0
        symbols = getattr(getattr(module.pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        for symbol in symbols:
            if ((isinstance(name, str) and symbol.name == name.encode())
                    or (isinstance(name, int) and symbol.ordinal == name)):
                if symbol.forwarder:
                    library, target = symbol.forwarder.decode().rsplit(".", 1)
                    target = int(target[1:]) if target.startswith("#") else target
                    other = self.load_module(library)
                    return self.export_address(other.base, target, depth + 1)
                return module.base + symbol.address
        return 0

    def setup_imports(self, module: Module) -> None:
        for descriptor in getattr(module.pe, "DIRECTORY_ENTRY_IMPORT", []):
            other = self.load_module(descriptor.dll.decode())
            for symbol in descriptor.imports:
                name = symbol.name.decode() if symbol.name else symbol.ordinal
                address = self.export_address(other.base, name)
                if not address:
                    raise RuntimeError(f"Missing import {other.name}!{name}")
                rva = symbol.address - module.pe.OPTIONAL_HEADER.ImageBase
                self.put64(module.base + rva, address)

    def unicode_string(self, descriptor: int, buffer: int, text: str) -> None:
        data = text.encode("utf-16le")
        if len(data) > 0x1F0:
            raise ValueError("Guest path exceeds the reserved Unicode buffer")
        self.write(buffer, data + b"\0\0")
        self.write(descriptor, struct.pack("<HHIQ", len(data), len(data) + 2, 0, buffer))

    def build_environment(self) -> None:
        self.put64(self.teb + 0x30, self.teb)
        self.put64(self.teb + 0x60, self.peb)
        self.put64(self.teb + 8, self.stack + self.stack_size)
        self.put64(self.teb + 16, self.stack)
        self.put64(self.teb + 0x40, 1000)
        self.put64(self.teb + 0x48, 1001)
        self.put64(self.peb + 0x10, self.target.base)
        self.put64(self.peb + 0x18, self.peb + 0x1000)
        self.put64(self.peb + 0x20, self.teb + 0xA000)
        self.put64(self.peb + 0x30, self.teb + 0x800)
        self.put32(self.peb + 0x118, 10)
        self.put32(self.peb + 0x11C, 0)
        self.put32(self.peb + 0x120, 19044)
        self.put32(self.peb + 0x128, 2)
        self.put32(0x7ffe0004, 0x1000000)
        self.put32(0x7ffe0260, 19044)
        self.put32(0x7ffe0264, 2)
        self.put32(0x7ffe026c, 10)
        self.put32(0x7ffe0270, 0)
        self.write(0x7ffe0030, 'C:\\Windows'.encode('utf-16le') + b'\0\0')
        self.ldr = self.peb + 0x1000
        api_map = self.alloc(len(self.api_set_blob))
        self.write(api_map, self.api_set_blob)
        self.put64(self.peb + 0x68, api_map)
        self.put32(self.ldr, 0x58)
        self.write(self.ldr + 4, b"\x01")
        self.build_module_list()
        params = self.teb + 0xA000
        self.put32(params, 0x1000)
        self.put32(params + 4, 0x1000)
        self.unicode_string(params + 0x60, self.teb + 0x9000, str(self.target_path))
        self.unicode_string(params + 0x70, self.teb + 0xD000, f'"{self.target_path}"')
        self.unicode_string(params + 0x38, self.teb + 0xE000, str(self.target_path.parent) + "\\")
        self.write(self.sentinel, b"\xcc")
        self.uc.reg_write(x86.UC_X86_REG_GS_BASE, self.teb)
        self.uc.reg_write(x86.UC_X86_REG_EFLAGS, 0x202)

    def build_module_list(self) -> None:
        if len(self.modules) > 24:
            raise RuntimeError("Guest module list capacity exceeded")
        nodes = []
        for i, module in enumerate(self.modules):
            node = type(self).teb + 0x10000 + i * 0x300
            nodes.append(node)
            self.put64(node + 0x30, module.base)
            self.put64(node + 0x38, module.base + module.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            self.put32(node + 0x40, module.size)
            self.unicode_string(node + 0x48, node + 0x100, module.name)
            self.unicode_string(node + 0x58, node + 0x200, module.name)
        for list_offset, entry_offset in ((0x10, 0), (0x20, 0x10), (0x30, 0x20)):
            head = self.ldr + list_offset
            listed = nodes[1:] if list_offset == 0x30 else nodes
            items = [head] + [node + entry_offset for node in listed]
            for i, item in enumerate(items):
                self.write(item, struct.pack("<QQ", items[(i + 1) % len(items)],
                                             items[(i - 1) % len(items)]))

    def setup_tls(self) -> None:
        array = self.teb + 0x18000
        self.put64(self.teb + 0x58, array)
        for i, module in enumerate((self.loader, self.target)):
            tls = getattr(module.pe, "DIRECTORY_ENTRY_TLS", None)
            if tls is None:
                continue
            tls = tls.struct
            size = tls.EndAddressOfRawData - tls.StartAddressOfRawData
            block = self.alloc(size + tls.SizeOfZeroFill)
            if size:
                self.write(block, self.read(tls.StartAddressOfRawData, size))
            self.put32(tls.AddressOfIndex, i)
            self.put64(array + i * 8, block)

    def thread_calls(self, start: int, parameter: int) -> list:
        calls = []
        for module in (self.loader, self.target):
            tls = getattr(module.pe, "DIRECTORY_ENTRY_TLS", None)
            if tls is not None:
                for i in range(64):
                    callback = self.u64(tls.struct.AddressOfCallBacks + i * 8)
                    if not callback:
                        break
                    calls.append((callback, (module.base, 2, 0)))
            if module is self.loader:
                calls.append((module.base + module.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                              (module.base, 2, 0)))
        calls.append((start, (parameter,)))
        return calls

    def create_thread(self, start: int, parameter: int, stack_size: int, suspended: bool) -> int:
        if len(self.threads) >= 16:
            raise RuntimeError("Guest thread count limit exceeded")
        if self.module_for_address(start) not in (self.loader, self.target):
            raise RuntimeError(f"Guest thread entry outside approved modules: {start:#x}")
        tid = self.next_thread
        self.next_thread += 1
        teb = self.alloc(0x20000)
        size = align(max(1024 * 1024, stack_size))
        stack = self.alloc(size)
        self.put64(teb + 0x30, teb)
        self.put64(teb + 0x60, self.peb)
        self.put64(teb + 8, stack + size)
        self.put64(teb + 16, stack)
        self.put64(teb + 0x40, 1000)
        self.put64(teb + 0x48, tid)
        array = teb + 0x18000
        self.put64(teb + 0x58, array)
        for i, module in enumerate((self.loader, self.target)):
            tls = getattr(module.pe, "DIRECTORY_ENTRY_TLS", None)
            if tls is not None:
                raw = tls.struct
                n = raw.EndAddressOfRawData - raw.StartAddressOfRawData
                block = self.alloc(n + raw.SizeOfZeroFill)
                if n:
                    self.write(block, module.pe.get_data(raw.StartAddressOfRawData - module.base, n))
                self.put64(array + i * 8, block)
        self.threads[tid] = {"teb": teb, "stack": stack, "stack_size": size,
                             "context": None, "calls": deque(self.thread_calls(start, parameter)),
                             "suspended": suspended, "wait": None, "exit": None}
        return tid

    def defer_thread(self, predicate, timeout: int):
        thread = self.threads[self.current_thread]
        if predicate():
            thread["wait"] = None
            return 0
        if timeout == 0:
            return 258
        if thread["wait"] is None:
            thread["wait"] = (predicate, None if timeout == 0xffffffff else self.time_counter + timeout * 10000)
        _, deadline = thread["wait"]
        if deadline is not None and self.time_counter >= deadline:
            thread["wait"] = None
            return 258
        self.thread_yield = True
        self.uc.emu_stop()
        return self.deferred

    def sleep_thread(self, milliseconds: int):
        thread = self.threads[self.current_thread]
        if thread["wait"] is None:
            wake = self.time_counter + max(1, milliseconds) * 10000
            thread["wait"] = (lambda: self.time_counter >= wake, wake)
        if thread["wait"][0]():
            thread["wait"] = None
            return 0
        self.thread_yield = True
        self.uc.emu_stop()
        return self.deferred

    def next_thread_call(self, thread: dict) -> bool:
        if not thread["calls"]:
            thread["exit"] = self.uc.reg_read(x86.UC_X86_REG_RAX) & 0xffffffff
            return False
        address, args = thread["calls"].popleft()
        stack = thread["stack"] + thread["stack_size"] - 0x108
        self.put64(stack, self.sentinel)
        for i, reg in enumerate(ARG_REGS):
            self.uc.reg_write(reg, args[i] if i < len(args) else 0)
        self.uc.reg_write(x86.UC_X86_REG_RSP, stack)
        self.uc.reg_write(x86.UC_X86_REG_RIP, address)
        return True

    def queue_timer(self, callback: int, parameter: int, due: int) -> int:
        tid = self.create_thread(callback, parameter, 0, True)
        wake = self.time_counter + due * 10000
        thread = self.threads[tid]
        thread["suspended"] = False
        thread["wait"] = (lambda: self.time_counter >= wake, wake)
        thread["calls"][-1] = (callback, (parameter, 1))
        self.timers[tid] = wake
        return tid

    def switch_thread(self) -> bool:
        current = self.threads[self.current_thread]
        current["context"] = self.uc.context_save()
        for tid, wake in list(self.timers.items()):
            thread = self.threads[tid]
            if thread["exit"] is not None:
                del self.timers[tid]
                continue
            if thread["wait"] and self.time_counter >= wake:
                thread["wait"] = None
        candidates = list(self.threads)
        start = candidates.index(self.current_thread) + 1
        candidates = candidates[start:] + candidates[:start]
        for tid in candidates:
            thread = self.threads[tid]
            if thread["exit"] is not None or thread["suspended"]:
                continue
            wait = thread["wait"]
            if wait and not wait[0]() and (wait[1] is None or self.time_counter < wait[1]):
                continue
            previous_tid = self.current_thread
            previous_teb = self.teb
            self.current_thread = tid
            self.teb = thread["teb"]
            if thread["context"] is not None:
                self.uc.context_restore(thread["context"])
            else:
                self.uc.reg_write(x86.UC_X86_REG_GS_BASE, self.teb)
                if not self.next_thread_call(thread):
                    self.current_thread = previous_tid
                    self.teb = previous_teb
                    continue
            self.uc.reg_write(x86.UC_X86_REG_GS_BASE, self.teb)
            return True
        wakeups = [t["wait"][1] for t in self.threads.values()
                   if t["exit"] is None and not t["suspended"] and t["wait"] and t["wait"][1] is not None]
        if wakeups:
            self.time_counter = max(self.time_counter, min(wakeups))
            return self.switch_thread()
        return False

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(address, size))

    def write(self, address: int, data: bytes) -> None:
        self.uc.mem_write(address, data)

    def u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def put64(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<Q", value & MASK64))

    def put32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def cstr(self, address: int, wide: bool = False) -> str:
        step = 2 if wide else 1
        data = bytearray()
        for offset in range(0, 32768, step):
            item = self.read(address + offset, step)
            if item == b"\0" * step:
                return data.decode("utf-16le" if wide else "utf-8")
            data.extend(item)
        raise RuntimeError(f"Unterminated guest string at {address:#x}")

    def alloc(self, size: int) -> int:
        mapped = align(max(1, size))
        if size < 0 or mapped > self.memory_limit:
            raise RuntimeError(f"Invalid guest allocation size: {size:#x}")
        for i, (address, capacity) in enumerate(self.free_regions):
            if capacity == mapped:
                self.free_regions.pop(i)
                self.map_region(address, mapped)
                self.uc.ctl_remove_cache(address, address + mapped)
                self.allocations[address] = (size, mapped)
                return address
        address = self.next_allocation
        self.next_allocation += mapped + PAGE
        if self.next_allocation >= 0x100000000:
            raise RuntimeError("Guest allocation address space exhausted")
        self.map_region(address, mapped)
        self.allocations[address] = (size, mapped)
        return address

    def free(self, address: int) -> bool:
        allocation = self.allocations.pop(address, None)
        if allocation is None:
            return False
        _, size = allocation
        self.uc.ctl_remove_cache(address, address + size)
        self.uc.mem_unmap(address, size)
        self.mapped_bytes -= size
        self.free_regions.append((address, size))
        return True

    def module_for_address(self, address: int) -> Module | None:
        return next((module for module in self.modules
                     if module.base <= address < module.base + module.size), None)

    def set_last_error(self, value: int) -> None:
        self.put32(self.teb + 0x68, value)

    def get_last_error(self) -> int:
        return struct.unpack("<I", self.read(self.teb + 0x68, 4))[0]

    def argument(self, index: int) -> int:
        if index < 4:
            return self.uc.reg_read(ARG_REGS[index])
        return self.u64(self.uc.reg_read(x86.UC_X86_REG_RSP) + 0x28 + (index - 4) * 8)

    def fail(self, message: str) -> None:
        self.error = message
        self.uc.emu_stop()

    def on_system_code(self, uc, address, size, user_data) -> None:
        name = self.exports.get(address)
        if name is None:
            self.fail(f"Execution inside unmodeled system code: {address:#x}")
            return
        self.api_counts[name] += 1
        self.api_total += 1
        try:
            result = self.api.dispatch(name, self.argument)
            if result is self.deferred:
                return
            if result is None:
                args = ", ".join(f"{self.argument(i):#x}" for i in range(4))
                self.fail(f"Unsupported API: {name}({args})")
                return
            stack = uc.reg_read(x86.UC_X86_REG_RSP)
            return_address = self.u64(stack)
            uc.reg_write(x86.UC_X86_REG_RAX, result & MASK64)
            uc.reg_write(x86.UC_X86_REG_RSP, stack + 8)
            uc.reg_write(x86.UC_X86_REG_RIP, return_address)
            if self.api_total % 256 == 0:
                self.thread_yield = len(self.threads) > 1
                uc.emu_stop()
        except (RuntimeError, ValueError, KeyError, UnicodeError, unicorn.UcError) as error:
            self.fail(f"{name}: {error}")

    def on_invalid_memory(self, uc, access, address, size, value, user_data) -> bool:
        self.error = (f"Unmapped/protected memory access {access} at {address:#x} "
                      f"({size} bytes), RIP={uc.reg_read(x86.UC_X86_REG_RIP):#x}")
        kind = 1 if access in (unicorn.UC_MEM_WRITE_UNMAPPED, unicorn.UC_MEM_WRITE_PROT) else 0
        if access in (unicorn.UC_MEM_FETCH_UNMAPPED, unicorn.UC_MEM_FETCH_PROT):
            kind = 8
        self.pending_exception = (0xc0000005, kind, address)
        return False

    def on_syscall(self, uc, user_data) -> None:
        self.fail(f"Direct syscall is not modeled at {uc.reg_read(x86.UC_X86_REG_RIP):#x}")

    def on_interrupt(self, uc, number, user_data) -> None:
        self.fail(f"Unhandled guest interrupt {number:#x}")

    def on_block(self, uc, address, size, user_data) -> None:
        if self.trace_blocks:
            self.recent_blocks.append(address)

    def on_target_write(self, uc, access, address, size, value, user_data) -> None:
        self.dirty_pages.update(range(address & -PAGE, align(address + size), PAGE))

    def on_original_code(self, uc, address, size, user_data) -> None:
        if self.stage != "exe-entry":
            self.fail(f"Unexpected target code execution during {self.stage}: {address:#x}")
            return
        rva = address - self.target.base
        section_offset = rva - self.original_code.VirtualAddress
        disk = self.target.pe.get_data(rva, min(32, self.original_code.Misc_VirtualSize - section_offset))
        if not disk or self.read(address, len(disk)) == disk:
            self.fail(f"Reached unchanged original code at {address:#x}; unpacking not established")
            return
        self.oep = address
        uc.emu_stop()

    def call(self, address: int, args: tuple[int, ...], deadline: float) -> None:
        stack = self.stack + self.stack_size - 0x1008
        self.put64(stack, self.sentinel)
        for index, reg in enumerate(ARG_REGS):
            self.uc.reg_write(reg, args[index] if index < len(args) else 0)
        self.uc.reg_write(x86.UC_X86_REG_RSP, stack)
        self.uc.reg_write(x86.UC_X86_REG_RIP, address)
        main = self.threads.setdefault(self.current_thread,
                   {"teb": self.teb, "stack": self.stack, "stack_size": self.stack_size,
                    "context": None, "calls": deque(), "suspended": False, "wait": None, "exit": None})
        main["exit"] = None
        while self.error is None and self.oep is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.error = f"Emulation time limit reached during {self.stage}"
                break
            self.thread_yield = False
            try:
                self.uc.emu_start(self.uc.reg_read(x86.UC_X86_REG_RIP), self.sentinel,
                                  timeout=max(1, int(remaining * 1_000_000)))
            except unicorn.UcError as error:
                pending = self.pending_exception
                self.pending_exception = None
                if pending is not None:
                    if self.seh.dispatch(*pending, deadline):
                        continue
                self.error = self.error or str(error)
                break
            if self.uc.query(unicorn.UC_QUERY_TIMEOUT):
                self.error = f"Emulation time limit reached during {self.stage}"
                break
            finished = self.uc.reg_read(x86.UC_X86_REG_RIP) == self.sentinel
            if finished:
                if self.current_thread == 1001:
                    break
                self.next_thread_call(self.threads[self.current_thread])
            if self.oep is None and (self.thread_yield or len(self.threads) > 1):
                if not self.switch_thread():
                    self.error = "All guest threads are blocked"
                    break
        if self.error:
            raise RuntimeError(self.error)

    def tls_callbacks(self, module: Module, deadline: float) -> None:
        tls = getattr(module.pe, "DIRECTORY_ENTRY_TLS", None)
        if tls is None:
            return
        array = tls.struct.AddressOfCallBacks
        for i in range(64):
            callback = self.u64(array + i * 8)
            if callback == 0:
                return
            self.call(callback, (module.base, 1, 0), deadline)
        raise RuntimeError("TLS callback count exceeds limit")

    def run(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        self.stage = "loader-tls"
        self.tls_callbacks(self.loader, deadline)
        self.stage = "loader-entry"
        print("Emulating ShippingBase.dll initialization", file=sys.stderr, flush=True)
        self.call(self.loader.base + self.loader.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                  (self.loader.base, 1, 0), deadline)
        if self.uc.reg_read(x86.UC_X86_REG_RAX) & 0xFFFFFFFF == 0:
            raise RuntimeError("ShippingBase.dll initialization returned FALSE")
        self.stage = "exe-tls"
        self.tls_callbacks(self.target, deadline)
        self.stage = "exe-entry"
        print("Emulating protected EXE entry", file=sys.stderr, flush=True)
        self.call(self.target.base + self.target.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                  (self.peb, 0, 0, 0), deadline)
        if self.oep is None:
            raise RuntimeError("EXE entry returned without reaching rewritten original code")

    def dump(self, output: Path, complete: bool) -> dict:
        status = "oep-reached" if complete else "partial"
        names = []
        for module in (self.target, self.loader):
            path = output / f"{module.path.stem}.{status}.mem"
            digest = hashlib.sha256()
            with path.open("xb") as stream:
                for offset in range(0, module.size, 1024 * 1024):
                    data = self.read(module.base + offset, min(1024 * 1024, module.size - offset))
                    digest.update(data)
                    stream.write(data)
            names.append({"path": str(path), "base": hex(module.base),
                          "size": module.size, "sha256": digest.hexdigest(),
                          "layout": "RVA; file offset = guest VA - image base"})
        return {"status": status, "oep": hex(self.oep) if self.oep else None,
                "stage": self.stage, "error": self.error,
                "rip": hex(self.uc.reg_read(x86.UC_X86_REG_RIP)),
                "mapped_bytes": self.mapped_bytes,
                "target_dirty_pages": len(self.dirty_pages),
                "seh_exceptions": self.seh.count,
                "guest_threads": len(self.threads),
                "recent_blocks": [hex(address) for address in self.recent_blocks],
                "api_calls": dict(self.api_counts), "dumps": names,
                "modules": [{"name": module.name, "base": hex(module.base),
                             "size": module.size} for module in self.modules]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New output directory; existing paths are refused")
    parser.add_argument("--system-dir", type=Path,
                        default=Path(os.environ["SystemRoot"]) / "System32" if "SystemRoot" in os.environ else None)
    parser.add_argument("--timeout", type=float, default=30, help="Emulation deadline in seconds")
    parser.add_argument("--memory-mib", type=int, default=1024, help="Mapped guest memory limit")
    parser.add_argument("--trace-blocks", action="store_true", help="Keep a bounded tail of executed basic blocks")
    args = parser.parse_args()
    if args.system_dir is None:
        parser.error("--system-dir is required outside Windows")
    if args.timeout <= 0 or args.memory_mib <= 0:
        parser.error("Timeout and memory limit must be positive")
    output = args.output.resolve()
    if output.exists():
        parser.error("Output directory already exists; choose a new path")
    start = time.monotonic()
    machine = None
    report = {"input": str(args.exe.resolve()), "input_sha256": sha256_file(args.exe),
              "format": "analysis-only RVA memory dump; not a runnable PE",
              "unicorn_version": unicorn.__version__, "status": "failed"}
    try:
        machine = Emulator(args.exe, args.system_dir, args.memory_mib * 1024 * 1024,
                           args.trace_blocks)
        machine.run(args.timeout)
    except (OSError, RuntimeError, ValueError, pefile.PEFormatError, unicorn.UcError) as error:
        report["error"] = str(error)
        if machine:
            machine.error = machine.error or str(error)
        print(f"Emulation stopped: {error}", file=sys.stderr)
    output.mkdir(parents=True, exist_ok=False)
    try:
        if machine:
            report.update(machine.dump(output, machine.oep is not None and machine.error is None))
        report["elapsed_seconds"] = round(time.monotonic() - start, 3)
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["status"] == "oep-reached" else 1
    finally:
        if machine:
            for module in machine.modules:
                module.pe.close()


if __name__ == "__main__":
    raise SystemExit(main())
