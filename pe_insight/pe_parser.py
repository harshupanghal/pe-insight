from datetime import datetime, UTC
from pathlib import Path

import pefile


SUSPICIOUS_API_RULES = {
    "process_injection_or_memory_manipulation": {
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "QueueUserAPC",
    },
    "process_execution": {
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
    },
    "dynamic_api_resolution": {
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
    },
    "registry_activity": {
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
    },
    "network_activity": {
        "WSAStartup",
        "socket",
        "connect",
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
    },
    "service_control": {
        "OpenSCManagerA",
        "OpenSCManagerW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
    },
    "anti_debug_or_environment_checks": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "QueryPerformanceCounter",
    },
}


def _get_machine_type(machine_value: int) -> str:
    machine_map = {
        0x14C: "x86",
        0x8664: "x64",
        0xAA64: "ARM64",
        0x1C0: "ARM",
    }
    return machine_map.get(machine_value, f"UNKNOWN (0x{machine_value:X})")


def _get_pe_format(optional_header_magic: int) -> str:
    if optional_header_magic == 0x10B:
        return "PE32"
    if optional_header_magic == 0x20B:
        return "PE32+"
    return f"UNKNOWN (0x{optional_header_magic:X})"


def _decode_section_name(name_bytes: bytes) -> str:
    return name_bytes.decode(errors="ignore").rstrip("\x00")


def _get_section_permissions(characteristics: int) -> dict:
    return {
        "read": bool(characteristics & 0x40000000),
        "write": bool(characteristics & 0x80000000),
        "execute": bool(characteristics & 0x20000000),
    }


def _classify_entropy(entropy: float) -> str:
    if entropy >= 7.4:
        return "high"
    if entropy >= 6.0:
        return "medium"
    return "low"


def _build_section_notes(section_name: str, permissions: dict, entropy: float) -> list[str]:
    notes = []

    if entropy >= 7.4:
        notes.append("high_entropy_section")

    if permissions["write"] and permissions["execute"]:
        notes.append("writable_and_executable")

    if not section_name:
        notes.append("blank_section_name")

    return notes


def extract_sections(pe: pefile.PE) -> list[dict]:
    sections = []

    for section in pe.sections:
        section_name = _decode_section_name(section.Name)
        permissions = _get_section_permissions(section.Characteristics)
        entropy = round(section.get_entropy(), 3)
        notes = _build_section_notes(section_name, permissions, entropy)

        section_info = {
            "name": section_name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "pointer_to_raw_data": hex(section.PointerToRawData),
            "characteristics_raw": hex(section.Characteristics),
            "permissions": permissions,
            "entropy": entropy,
            "entropy_level": _classify_entropy(entropy),
            "notes": notes,
        }

        sections.append(section_info)

    return sections


def build_anomaly_summary(sections: list[dict]) -> list[str]:
    findings = []

    high_entropy_count = sum(1 for section in sections if section["entropy"] >= 7.4)
    rwx_count = sum(
        1
        for section in sections
        if section["permissions"]["write"] and section["permissions"]["execute"]
    )

    if high_entropy_count > 0:
        findings.append(f"{high_entropy_count} section(s) have high entropy")

    if rwx_count > 0:
        findings.append(f"{rwx_count} section(s) are writable and executable")

    return findings


def _decode_bytes(value: bytes | None) -> str | None:
    if value is None:
        return None
    return value.decode(errors="ignore")


def extract_imports(pe: pefile.PE) -> tuple[list[dict], list[dict], list[str]]:
    imports_data = []
    suspicious_matches = []
    import_summary = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        import_summary.append("No import table found")
        return imports_data, suspicious_matches, import_summary

    total_imported_functions = 0

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = _decode_bytes(entry.dll) or "UNKNOWN_DLL"
        dll_functions = []

        for imp in entry.imports:
            func_name = _decode_bytes(imp.name)
            import_record = {
                "name": func_name,
                "ordinal": imp.ordinal,
                "address": hex(imp.address) if imp.address is not None else None,
            }
            dll_functions.append(import_record)

            if func_name:
                total_imported_functions += 1

                for category, api_names in SUSPICIOUS_API_RULES.items():
                    if func_name in api_names:
                        suspicious_matches.append(
                            {
                                "dll": dll_name,
                                "api": func_name,
                                "category": category,
                            }
                        )

        imports_data.append(
            {
                "dll": dll_name,
                "import_count": len(dll_functions),
                "functions": dll_functions,
            }
        )

    import_summary.append(f"Imported DLL count: {len(imports_data)}")
    import_summary.append(f"Imported function count: {total_imported_functions}")

    if suspicious_matches:
        import_summary.append(f"Suspicious API matches: {len(suspicious_matches)}")
    else:
        import_summary.append("No suspicious API matches by current rules")

    return imports_data, suspicious_matches, import_summary


def _parse_pe_core(pe: pefile.PE, file_name: str) -> dict:
    compile_timestamp = pe.FILE_HEADER.TimeDateStamp
    compiled_at = datetime.fromtimestamp(compile_timestamp, UTC).isoformat()

    sections = extract_sections(pe)
    anomaly_summary = build_anomaly_summary(sections)
    imports_data, suspicious_imports, import_summary = extract_imports(pe)

    return {
        "file_name": file_name,
        "pe_format": _get_pe_format(pe.OPTIONAL_HEADER.Magic),
        "machine": _get_machine_type(pe.FILE_HEADER.Machine),
        "machine_raw": hex(pe.FILE_HEADER.Machine),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "compile_timestamp_raw": compile_timestamp,
        "compile_timestamp_utc": compiled_at,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "anomaly_summary": anomaly_summary,
        "import_summary": import_summary,
        "suspicious_imports": suspicious_imports,
        "imports": imports_data,
        "sections": sections,
    }


def parse_pe_file(file_path: Path) -> dict:
    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError as exc:
        raise ValueError(f"Not a valid PE file: {exc}") from exc

    try:
        return _parse_pe_core(pe, file_path.name)
    finally:
        pe.close()


def parse_pe_bytes(file_bytes: bytes, file_name: str) -> dict:
    try:
        pe = pefile.PE(data=file_bytes)
    except pefile.PEFormatError as exc:
        raise ValueError(f"Not a valid PE file: {exc}") from exc

    try:
        return _parse_pe_core(pe, file_name)
    finally:
        pe.close()