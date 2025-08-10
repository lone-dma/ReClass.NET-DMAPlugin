#include "vmmdll.h"
#include "ReClassNET_Plugin.hpp"
#include <algorithm>
#include <cstdint>
#include <vector>
#include <filesystem>

VMM_HANDLE _vmm = NULL;
const bool _hasMemMap = std::filesystem::exists("mmap.txt");

extern "C" void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess) {
	if (callbackProcess == nullptr) {
		return;
	}

	if (!_vmm) {
		if (_hasMemMap) {
			LPCSTR argv[] = { "-device", "fpga", "-memmap", "mmap.txt", "-waitinitialize" };
			_vmm = VMMDLL_Initialize(5, argv);
		}
		else {
			LPCSTR argv[] = { "-device", "fpga", "-waitinitialize" };
			_vmm = VMMDLL_Initialize(3, argv);
		}

		if (!_vmm) {
			MessageBoxA(0, "FAIL: VMMDLL_Initialize", 0, MB_OK | MB_ICONERROR);

			ExitProcess(-1);
		}
	}

	BOOL result;
	ULONG64 cPIDs = 0;
	DWORD i, * pPIDs = NULL;

	result =
		VMMDLL_PidList(_vmm, NULL, &cPIDs) && (pPIDs = (DWORD*)LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD))) && VMMDLL_PidList(_vmm, pPIDs, &cPIDs);

	if (!result) {
		LocalFree(pPIDs);
		return;
	}

	for (i = 0; i < cPIDs; i++) {
		DWORD dwPID = pPIDs[i];

		VMMDLL_PROCESS_INFORMATION info;
		SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
		ZeroMemory(&info, cbInfo);
		info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
		info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

		result = VMMDLL_ProcessGetInformation(_vmm, dwPID, &info, &cbInfo);

		if (result) {
			EnumerateProcessData data = {};
			data.Id = dwPID;
			MultiByteToUnicode(info.szNameLong, data.Name, PATH_MAXIMUM_LENGTH);

			LPSTR szPathUser = VMMDLL_ProcessGetInformationString(_vmm, dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);

			if (szPathUser) {
				MultiByteToUnicode(szPathUser, data.Path, PATH_MAXIMUM_LENGTH);
			}

			callbackProcess(&data);
		}
	}

	LocalFree(pPIDs);
}

extern "C" void RC_CallConv EnumerateRemoteSectionsAndModules(
    RC_Pointer handle,
    EnumerateRemoteSectionsCallback callbackSection,
    EnumerateRemoteModulesCallback callbackModule)
{
    if (!callbackSection && !callbackModule) return;

    // RC_Pointer -> DWORD pid (safe on x64)
    const DWORD dwPID = static_cast<DWORD>(reinterpret_cast<uintptr_t>(handle));

    // tiny helper: copy wchar_t* into RC_UnicodeChar[]
    auto copyWideToRC = [](const wchar_t* src, RC_UnicodeChar* dst, size_t cap) {
        if (!dst || cap == 0) return;
        if (!src) { dst[0] = 0; return; }
        const size_t n = wcsnlen(src, cap - 1);
        for (size_t i = 0; i < n; ++i) dst[i] = static_cast<RC_UnicodeChar>(src[i]);
        dst[n] = 0;
        };

    // ----- PTE -> sections
    PVMMDLL_MAP_PTE pMemMapEntries = nullptr;
    if (!VMMDLL_Map_GetPte(_vmm, dwPID, TRUE, &pMemMapEntries) || !pMemMapEntries) {
        MessageBoxA(nullptr, "FAIL: VMMDLL_Map_GetPte", nullptr, MB_OK | MB_ICONERROR);
        ExitProcess(-1);
    }

    std::vector<EnumerateRemoteSectionData> sections;
    sections.reserve(static_cast<size_t>(pMemMapEntries->cMap));

    for (ULONG64 i = 0; i < pMemMapEntries->cMap; ++i) {
        const auto* m = &pMemMapEntries->pMap[i];

        EnumerateRemoteSectionData s{};
        s.BaseAddress = reinterpret_cast<RC_Pointer>(m->vaBase);
        s.Size = static_cast<RC_Size>(m->cPages) << 12;
        s.Protection = SectionProtection::NoAccess;
        s.Category = SectionCategory::Unknown;

        if (m->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS)  s.Protection |= SectionProtection::Read;
        if (m->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W)   s.Protection |= SectionProtection::Write;
        if (!(m->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX)) s.Protection |= SectionProtection::Execute;

        if (m->wszText && m->wszText[0]) {
            if (wcsncmp(m->wszText, L"HEAP", 4) == 0 || wcsncmp(m->wszText, L"[HEAP", 5) == 0) {
                s.Type = SectionType::Private;
            }
            else {
                s.Type = SectionType::Image;
                copyWideToRC(m->wszText, s.ModulePath, PATH_MAXIMUM_LENGTH);
            }
        }
        else {
            s.Type = SectionType::Mapped;
        }

        sections.emplace_back(std::move(s));
    }
    VMMDLL_MemFree(pMemMapEntries);

    // Sort once so lower_bound works
    std::sort(sections.begin(), sections.end(),
        [](const auto& a, const auto& b) {
            return reinterpret_cast<uintptr_t>(a.BaseAddress) < reinterpret_cast<uintptr_t>(b.BaseAddress);
        });

    // ----- Modules
    PVMMDLL_MAP_MODULE pModuleEntries = nullptr;
    if (!VMMDLL_Map_GetModule(_vmm, dwPID, &pModuleEntries, 0) || !pModuleEntries) { // flags = 0 (NOT NULL)
        MessageBoxA(nullptr, "FAIL: VMMDLL_Map_GetModule", nullptr, MB_OK | MB_ICONERROR);
        ExitProcess(-1);
    }

    for (ULONG64 i = 0; i < pModuleEntries->cMap; ++i) {
        const auto& mod = pModuleEntries->pMap[i];

        if (callbackModule) {
            EnumerateRemoteModuleData md{};
            md.BaseAddress = reinterpret_cast<RC_Pointer>(mod.vaBase);
            md.Size = static_cast<RC_Size>(mod.cbImageSize);
            if (mod.wszText) copyWideToRC(mod.wszText, md.Path, PATH_MAXIMUM_LENGTH);
            callbackModule(&md);
        }

        // Optional: classify CODE/DATA; known to be flaky in some targets, keep guarded
        DWORD cSections = 0;
        if (!VMMDLL_ProcessGetSections(_vmm, dwPID, mod.wszText, nullptr, 0, &cSections) || cSections == 0)
            continue;

        std::vector<IMAGE_SECTION_HEADER> peSecs(cSections);
        if (!VMMDLL_ProcessGetSections(_vmm, dwPID, mod.wszText, peSecs.data(), cSections, &cSections) || cSections == 0)
            continue;

        for (DWORD j = 0; j < cSections; ++j) {
            const auto& sh = peSecs[j];
            const uintptr_t sectionAddress = static_cast<uintptr_t>(mod.vaBase + sh.VirtualAddress);

            // lower_bound by the section's VA (not module base)
            auto it = std::lower_bound(sections.begin(), sections.end(), reinterpret_cast<LPVOID>(sectionAddress),
                [](const auto& lhs, const LPVOID rhs) {
                    return reinterpret_cast<uintptr_t>(lhs.BaseAddress) < reinterpret_cast<uintptr_t>(rhs);
                });

            for (auto k = it; k != sections.end(); ++k) {
                const uintptr_t start = reinterpret_cast<uintptr_t>(k->BaseAddress);
                const uintptr_t end = start + static_cast<uintptr_t>(k->Size);

                if (sectionAddress < start) break;     // sorted; no match further
                if (sectionAddress >= end) continue;    // try next

                // PE short name isn't null-terminated; fix that
                char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
                std::memcpy(name, sh.Name, IMAGE_SIZEOF_SHORT_NAME);

                if (!std::strcmp(name, ".text") || !std::strcmp(name, "code")) {
                    k->Category = SectionCategory::CODE;
                }
                else if (!std::strcmp(name, ".data") ||
                    !std::strcmp(name, "data") ||
                    !std::strcmp(name, ".rdata") ||
                    !std::strcmp(name, ".idata")) {
                    k->Category = SectionCategory::DATA;
                }
                MultiByteToUnicode(name, k->Name, IMAGE_SIZEOF_SHORT_NAME);
                break; // found the owning region
            }
        }
    }
    VMMDLL_MemFree(pModuleEntries);

    if (callbackSection) {
        for (auto& s : sections) callbackSection(&s);
    }
}

extern "C" RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess) {
	return id;
}

extern "C" bool RC_CallConv IsProcessValid(RC_Pointer handle) {
	VMMDLL_PROCESS_INFORMATION info;
	SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
	ZeroMemory(&info, cbInfo);
	info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

	if (VMMDLL_ProcessGetInformation(_vmm, (DWORD)handle, &info, &cbInfo)) {
		return true;
	}

	return false;
}

extern "C" void RC_CallConv CloseRemoteProcess(RC_Pointer handle)
{
	if (_vmm)
	{
		VMMDLL_Close(_vmm);
		_vmm = NULL;
	}
}

extern "C" bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);

	if (VMMDLL_MemRead(_vmm, (DWORD)handle, (ULONG64)address, (PBYTE)buffer, size)) {
		return true;
	}

	return false;
}

extern "C" bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	// Mem Writing Not Supported!
	return false;
}

////////////////////////////////////////
////////////////////////////////////////
// Remote debugging is not supported
////////////////////////////////////////
////////////////////////////////////////

extern "C" void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action) {
}

extern "C" bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id) {
	return false;
}

extern "C" void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id) {
}

extern "C" bool RC_CallConv AwaitDebugEvent(DebugEvent * evt, int timeoutInMilliseconds) {
	return false;
}

extern "C" void RC_CallConv HandleDebugEvent(DebugEvent * evt) {
}

extern "C" bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type,
	HardwareBreakpointSize size, bool set) {
	return false;
}
