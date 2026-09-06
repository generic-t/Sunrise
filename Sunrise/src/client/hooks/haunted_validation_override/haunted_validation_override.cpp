#include "haunted_validation_override.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include "../../../core/logging/log.h"

namespace sunrise::client::hooks::haunted_validation_override {
namespace {

/** Destiny validation continuation immediately before its native row comparison. */
constexpr std::uintptr_t kValidationContinuationRva = 0x4364FF;
/** Original instruction: mov rax, rcx. The breakpoint handler emulates it. */
constexpr std::array<std::uint8_t, 3> kOriginalInstruction{0x48, 0x8B, 0xC1};
/** Descriptor written by the observed Haunted path. */
constexpr std::array<std::uint32_t, 4> kHauntedDescriptor{
    0x81550015, 0x80809258, 0x000002EC, 0x00000000};
constexpr std::uint32_t kHauntedValidationChild = 0x8150A9FC;
constexpr std::uintptr_t kValidationOffset = 0x10C;
constexpr std::uintptr_t kValidationStride = 4;
constexpr std::uint32_t kHauntedValidationRow = 13;

HMODULE g_gameImage{};
PVOID g_vectoredHandler{};
std::uint8_t g_originalFirstByte{};
std::atomic<bool> g_installed{};

[[nodiscard]] bool read_bytes(std::uintptr_t address,
                              void* output,
                              std::size_t bytes) noexcept {
    if (address < 0x10000 || output == nullptr || bytes == 0) {
        return false;
    }
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(),
                             reinterpret_cast<const void*>(address),
                             output,
                             bytes,
                             &copied) != FALSE
           && copied == bytes;
}

[[nodiscard]] bool write_code_byte(std::uintptr_t address,
                                   std::uint8_t value) noexcept {
    DWORD originalProtection = 0;
    DWORD ignored = 0;
    if (VirtualProtect(reinterpret_cast<void*>(address),
                       sizeof value,
                       PAGE_EXECUTE_READWRITE,
                       &originalProtection) == FALSE) {
        return false;
    }
    *reinterpret_cast<volatile std::uint8_t*>(address) = value;
    FlushInstructionCache(GetCurrentProcess(),
                          reinterpret_cast<const void*>(address),
                          sizeof value);
    const bool restored = VirtualProtect(reinterpret_cast<void*>(address),
                                         sizeof value,
                                         originalProtection,
                                         &ignored) != FALSE;
    return restored;
}

[[nodiscard]] bool descriptor_matches(const CONTEXT& context) noexcept {
    std::array<std::uint32_t, kHauntedDescriptor.size()> descriptor{};
    if (context.Rdi < 0x10000
        || !read_bytes(static_cast<std::uintptr_t>(context.Rdi),
                       descriptor.data(),
                       sizeof descriptor)) {
        return false;
    }
    return descriptor == kHauntedDescriptor;
}

[[nodiscard]] bool row13_matches(const CONTEXT& context) noexcept {
    const std::uintptr_t base = static_cast<std::uintptr_t>(context.Rbx);
    constexpr std::uintptr_t rowOffset =
        kValidationOffset + kHauntedValidationRow * kValidationStride;
    if (base < 0x10000 || base > UINTPTR_MAX - rowOffset) {
        return false;
    }
    std::uint32_t value = 0;
    return read_bytes(base + rowOffset, &value, sizeof value)
           && value == kHauntedValidationChild;
}

LONG CALLBACK breakpoint_handler(EXCEPTION_POINTERS* pointers) noexcept {
    if (!g_installed.load(std::memory_order_acquire)
        || pointers == nullptr || pointers->ExceptionRecord == nullptr
        || pointers->ContextRecord == nullptr
        || pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT& context = *pointers->ContextRecord;
    const std::uintptr_t continuation =
        reinterpret_cast<std::uintptr_t>(g_gameImage) + kValidationContinuationRva;
    // Windows reports the faulting instruction in ExceptionAddress. Do not infer it
    // from the CPU's post-INT3 RIP: the dispatched Windows context adjusts that RIP.
    if (reinterpret_cast<std::uintptr_t>(pointers->ExceptionRecord->ExceptionAddress)
        != continuation) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Preserve the original mov rax, rcx for every non-Haunted invocation.
    context.Rax = context.Rcx;
    if (context.Rcx == 0 && descriptor_matches(context) && row13_matches(context)) {
        context.Rcx = kHauntedValidationRow;
        context.Rax = kHauntedValidationRow;
    }
    // Skip the three-byte instruction whose first byte is the breakpoint.
    context.Rip = continuation + kOriginalInstruction.size();
    return EXCEPTION_CONTINUE_EXECUTION;
}

void report_status(const char* result, const char* reason) noexcept {
    char line[256]{};
    const int written = std::snprintf(
        line,
        sizeof line,
        "ev=activity stage=haunted_validation_override result=%s target_rva=0x%llX reason=%s",
        result,
        static_cast<unsigned long long>(kValidationContinuationRva),
        reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         std::strcmp(result, "installed") == 0
                             ? core::log::Level::info
                             : core::log::Level::warn,
                         {line, static_cast<std::size_t>(written)});
    }
}

} // namespace

bool install() noexcept {
    if (g_installed.load(std::memory_order_acquire)) {
        return true;
    }
    g_gameImage = GetModuleHandleW(nullptr);
    if (g_gameImage == nullptr) {
        report_status("not_installed", "game_image");
        return false;
    }
    const auto target = reinterpret_cast<std::uintptr_t>(g_gameImage)
                        + kValidationContinuationRva;
    std::array<std::uint8_t, kOriginalInstruction.size()> instruction{};
    if (!read_bytes(target, instruction.data(), instruction.size())
        || instruction != kOriginalInstruction) {
        report_status("not_installed", "instruction_mismatch");
        return false;
    }
    g_originalFirstByte = instruction[0];
    g_vectoredHandler = AddVectoredExceptionHandler(1, &breakpoint_handler);
    if (g_vectoredHandler == nullptr) {
        report_status("not_installed", "veh");
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    if (!write_code_byte(target, 0xCC)) {
        // The byte may already have been written before protection restoration failed.
        // Restore it before removing the handler; retain ownership if cleanup fails.
        report_status("install_failed", "patch");
        (void)uninstall();
        return false;
    }
    report_status("installed", "none");
    return true;
}

bool uninstall() noexcept {
    if (!g_installed.load(std::memory_order_acquire)) {
        return true;
    }
    const auto target = reinterpret_cast<std::uintptr_t>(g_gameImage)
                        + kValidationContinuationRva;
    // Keep servicing our breakpoint until its instruction has been restored.
    if (!write_code_byte(target, g_originalFirstByte)) {
        report_status("uninstall_failed", "patch_handler_retained");
        return false;
    }
    if (RemoveVectoredExceptionHandler(g_vectoredHandler) == 0) {
        report_status("uninstall_failed", "veh_handler_retained");
        return false;
    }
    g_installed.store(false, std::memory_order_release);
    g_vectoredHandler = nullptr;
    g_gameImage = nullptr;
    report_status("uninstalled", "none");
    return true;
}

} // namespace sunrise::client::hooks::haunted_validation_override
