#include "common.h"
#include "miniz.h"

extern const BYTE g_packed_data[];
extern const BYTE g_packed_end[];

static BOOL verify_DOS_header(IMAGE_DOS_HEADER *dos) {
    WORD magicBytes = dos->e_magic;
    if (magicBytes != IMAGE_DOS_SIGNATURE) {
        WARN(
            "Invalid DOS header (IMAGE_DOS_HEADER->e_magic = 0x%04hx)",
            (unsigned short)magicBytes
        );
        return FALSE;
    }
    return TRUE;
}

static BOOL verify_NT_header(IMAGE_NT_HEADERS64 *nt) {
    DWORD ntSign = nt->Signature;
    if (ntSign != IMAGE_NT_SIGNATURE) {
        WARN(
            "Invalid NT header (IMAGE_NT_HEADERS64->Signature = 0x%08lx)",
            (unsigned long)ntSign
        );
        return FALSE;
    }
    return TRUE;
}

static BOOL verify_machine(IMAGE_FILE_HEADER *file) {
    WORD machine = file->Machine;
    if (machine != IMAGE_FILE_MACHINE_AMD64) {
        WARN(
            "Architecture not supported (IMAGE_FILE_HEADER->Machine = 0x%04hx)",
            (unsigned short)machine
        );
        return FALSE;
    }
    return TRUE;
}

static BOOL map_image(BYTE *data, PE_CONTEXT *ctx) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)data;
    if (!verify_DOS_header(dos)) return FALSE;
    
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(data + dos->e_lfanew);
    if (!verify_NT_header(nt)) return FALSE;

    // Verify x64 architecture (0x8664)
    IMAGE_FILE_HEADER *file = (IMAGE_FILE_HEADER *)&nt->FileHeader;
    if (!verify_machine(file)) return FALSE;

    // Allocate memory
    BYTE *image = (BYTE *)VirtualAlloc(
        NULL,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!image) return FALSE;

    // Load PE data into the allocated memory
    memcpy(image, data, nt->OptionalHeader.SizeOfHeaders);

    // Map each sections
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // Skip if the section is empty
        if (sections[i].SizeOfRawData == 0) continue;

        // Allocate each sections
        memcpy(
            image + sections[i].VirtualAddress,
            data + sections[i].PointerToRawData,
            sections[i].SizeOfRawData
        );
    }

    // Save PE contexts
    ctx->base = image;
    ctx->size = nt->OptionalHeader.SizeOfImage;
    ctx->dos = (IMAGE_DOS_HEADER *)image;
    ctx->nt = (IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    ctx->sections = IMAGE_FIRST_SECTION(ctx->nt);
    ctx->oep = ctx->nt->OptionalHeader.AddressOfEntryPoint;

    return TRUE;
}

static BOOL relocate_pe(PE_CONTEXT *ctx) {
    // delta = loaded_image_base - preferred_image_base
    ULONG_PTR delta = (ULONG_PTR)ctx->base - ctx->nt->OptionalHeader.ImageBase;
    if (delta == 0) {
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY reloc_dir = ctx->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.Size == 0) {
        return FALSE;
    }

    IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(ctx->base + reloc_dir.VirtualAddress);

    while (reloc->VirtualAddress > 0) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *list = (WORD *)(reloc + 1);

        for (DWORD i = 0; i < count; i++) {
            if (list[i] != 0) {
                DWORD type = list[i] >> 12;
                DWORD offset = list[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR *patch_addr = (ULONG_PTR *)(ctx->base + reloc->VirtualAddress + offset);
                    *patch_addr += delta;
                }
            }
        }
        reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
    }

    return TRUE;
}

static BOOL resolve_iat(PE_CONTEXT *ctx) {
    IMAGE_DATA_DIRECTORY import_dir = ctx->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) return 1;

    IMAGE_IMPORT_DESCRIPTOR *import_desc = (IMAGE_IMPORT_DESCRIPTOR *)(ctx->base + import_dir.VirtualAddress);

    for (; import_desc->Name; import_desc++) {
        char *mod_name = (char *)(ctx->base + import_desc->Name);
        HMODULE h_mod = LoadLibraryA(mod_name);
        if (!h_mod) {
            WARN(
                "Failed to load library: %s",
                mod_name
            );
            return FALSE;
        }

        IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(ctx->base + import_desc->FirstThunk);
        IMAGE_THUNK_DATA64 *original_thunk = import_desc->OriginalFirstThunk ?
            (IMAGE_THUNK_DATA64 *)(ctx->base + import_desc->OriginalFirstThunk) : thunk;

        for (; original_thunk->u1.AddressOfData; thunk++, original_thunk++) {
            if (IMAGE_SNAP_BY_ORDINAL64(original_thunk->u1.Ordinal)) {
                LPCSTR ordinal = (LPCSTR)IMAGE_ORDINAL64(original_thunk->u1.Ordinal);
                thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_mod, ordinal);
            } else {
                IMAGE_IMPORT_BY_NAME *iibn = (IMAGE_IMPORT_BY_NAME *)(ctx->base + original_thunk->u1.AddressOfData);
                thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_mod, (LPCSTR)iibn->Name);
            }
            if (!thunk->u1.Function) {
                WARN("Failed to resolve import function");
                return FALSE;
            }
        }
    }
    return TRUE;
}

int main() {
    PE_CONTEXT ctx;
    ORIGINAL_ENTRY_POINT oep;

    uLongf uncompressed_size = *(UINT32 *)g_packed_data;

    const BYTE *compressed_data = g_packed_data + 4;
    uLongf compressed_size = (uLongf)(g_packed_end - g_packed_data) - 4;

    BYTE *decompressed_data = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uncompressed_size);
    if (!decompressed_data) {
        return -1;
    }

    int z_res = uncompress(decompressed_data, &uncompressed_size, compressed_data, compressed_size);
    if (z_res != Z_OK) {
        WARN("miniz decompression failed (code: %d)", z_res);
        HeapFree(GetProcessHeap(), 0, decompressed_data);
        return -1;
    }

    if (!map_image(decompressed_data, &ctx)) {
        HeapFree(GetProcessHeap(), 0, decompressed_data);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, decompressed_data);

    if (!relocate_pe(&ctx)) {
        goto cleanup;
    }

    if (!resolve_iat(&ctx)) {
        goto cleanup;
    }

    oep = (ORIGINAL_ENTRY_POINT)(ctx.base + ctx.oep);
    oep();

    VirtualFree(ctx.base, 0, MEM_RELEASE);
    return 0;
cleanup:
    VirtualFree(ctx.base, 0, MEM_RELEASE);
    return 1;
}