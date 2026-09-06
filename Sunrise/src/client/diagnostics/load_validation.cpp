#include "load_validation.h"

#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string_view>
#include "../../core/logging/log.h"
#include "../../server/bap/runtime.h"
#include "../hooks/bootflow/bootflow_hook_lifecycle.h"
#include "../hooking/detour.h"
#include "../patterns/image_scan.h"
#include "../patterns/signature_text.h"

namespace sunrise::client::diagnostics::load_validation {
namespace {
using Gate = bool(__fastcall*)(void*);
// Same verified function/layout as checkpoint abb8af5. No outer-msg5 hook or return override.
constexpr std::string_view kSignatureText =
    "48 89 5C 24 18 48 89 7C 24 20 55 48 8B EC 48 83 EC 40 48 8B B9 08 08 00 00 48 8B 07 "
    "48 8B 48 08 48 8B 59 10 48 8B CF E8 ? ? ? ? 44 8B C0";
constexpr auto kSignature = patterns::signature<patterns::signature_length(kSignatureText)>(
    kSignatureText);
constexpr std::size_t kStride = 0x88;
constexpr std::uint64_t kSampleIntervalMs = 250;
SRWLOCK g_lifecycleLock = SRWLOCK_INIT;
SRWLOCK g_snapshotLock = SRWLOCK_INIT;
SRWLOCK g_captureLock = SRWLOCK_INIT;
hooking::detour::Handle g_handle{};
Gate g_target{};
bool g_accepting{};
std::atomic_uint g_active{};
std::atomic_bool g_installed{};
std::uint64_t g_lastSample{}; // Protected by the non-waiting capture lease.
Snapshot g_snapshot{};
PlayerSnapshot g_player{};
// One bounded scratch buffer, not a 0.5-MB fiber local or one allocation per game thread.
std::array<std::byte, kRecordCapacity * kStride> g_bytes{};
Snapshot g_sample{};
struct ActivitySource {
    std::uintptr_t client{}, slot{}, roster{};
    std::uint64_t sessionId{};
    bool receipt{};
};
SRWLOCK g_sourceLock = SRWLOCK_INIT;
std::array<ActivitySource, 4> g_sources{};
std::atomic<std::uintptr_t> g_gateOwner{};
std::atomic<std::uint64_t> g_worldReadyTick{};
std::uint64_t g_lastPostSample{}; // Protected by g_captureLock.
constexpr std::uint64_t kPostSampleIntervalMs = 2'000;
// Existing membership-probe layout. The embedded sync owner was independently observed at
// roster+0x28 by the seed hook; require that witness instead of blindly trusting an offset.
constexpr std::size_t kEstablishedSessionOffset = 16352;
constexpr std::size_t kSlotOffset = 27672;
constexpr std::size_t kSyncOwnerOffset = 0x28;

bool read(std::uintptr_t address, void* out, std::size_t bytes) noexcept {
    SIZE_T copied = 0;
    return address >= 0x10000
           && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                                out, bytes, &copied) != FALSE && copied == bytes;
}
template <typename T> T field(const std::byte* bytes, std::size_t offset) noexcept {
    T value{};
    std::memcpy(&value, bytes + offset, sizeof value);
    return value;
}

/** Copies bytes only. Caller owns the scratch lease and establishes the observation context. */
void capture_pool(Snapshot& out) noexcept {
    std::uintptr_t pool = 0;
    std::array<std::byte, 0x20> header{}, after{};
    if (out.owner >= 0x10000 && read(out.owner + 0x808, &pool, sizeof pool)
        && read(pool, header.data(), header.size())) {
        const auto base = field<std::uintptr_t>(header.data(), 0x08);
        const auto stride = field<std::uint32_t>(header.data(), 0x10);
        const auto capacity = field<std::uint32_t>(header.data(), 0x14);
        const auto count = field<std::uint32_t>(header.data(), 0x18);
        if (stride == kStride && capacity != 0 && capacity <= kRecordCapacity
            && count <= capacity
            && (count == 0 || read(base, g_bytes.data(), count * kStride))
            && read(pool, after.data(), after.size()) && header == after) {
            out.readable = true;
            out.count = count;
            for (std::size_t i = 0; i < count; ++i) {
                const std::byte* bytes = g_bytes.data() + i * kStride;
                Record& row = out.records[i];
                row.key = field<std::uint32_t>(bytes, 0);
                row.type = field<std::uint8_t>(bytes, 4);
                row.slot = field<std::uint16_t>(bytes, 6);
                row.senseSchema = field<std::uint32_t>(bytes, 8);
                row.authSchema = field<std::uint32_t>(bytes, 0x0C);
                row.unseeded = field<std::uint8_t>(bytes, 0x18);
                row.bubble = field<std::uint32_t>(bytes, 0x68);
                const auto schema = [](std::uint32_t value) noexcept {
                    return value == 0xFFFFFFFFU || (value & 0xFFFF0000U) == 0x80800000U;
                };
                row.valid = row.type <= 127 && bytes[5] == std::byte{} && row.slot <= 32767
                            && schema(row.senseSchema) && schema(row.authSchema);
                if (!row.valid) ++out.invalidHeaders;
            }
        }
    }
}

/** Owner is borrowed inside this intercepted call. The post-load path revalidates its parent. */
void observe(void* owner, bool gatePassed) noexcept {
    if (!TryAcquireSRWLockExclusive(&g_captureLock)) return;
    const std::uint64_t now = GetTickCount64();
    if (now - g_lastSample < kSampleIntervalMs) {
        ReleaseSRWLockExclusive(&g_captureLock);
        return;
    }
    g_lastSample = now;
    Snapshot& out = g_sample;
    out = {};
    out.owner = reinterpret_cast<std::uintptr_t>(owner);
    out.tick = now;
    out.observed = true;
    out.nativeGatePassed = gatePassed;
    capture_pool(out);
    AcquireSRWLockExclusive(&g_snapshotLock);
    const bool changed = !g_snapshot.observed || g_snapshot.owner != out.owner
                         || g_snapshot.readable != out.readable
                         || g_snapshot.count != out.count
                         || g_snapshot.invalidHeaders != out.invalidHeaders
                         || g_snapshot.nativeGatePassed != out.nativeGatePassed;
    g_snapshot = out;
    ReleaseSRWLockExclusive(&g_snapshotLock);
    if (changed) {
        std::array<char, 240> line{};
        const int n = std::snprintf(line.data(), line.size(),
            "ev=load_validation stage=native_pool readable=%u records=%zu invalid_headers=%zu "
            "native_seed_gate=%u owner=0x%llX",
            out.readable ? 1U : 0U, out.count, out.invalidHeaders, gatePassed ? 1U : 0U,
            static_cast<unsigned long long>(out.owner));
        if (n > 0 && static_cast<std::size_t>(n) < line.size())
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(n)});
    }
    ReleaseSRWLockExclusive(&g_captureLock);
}

__declspec(noinline) bool __fastcall seeded_gate(void* owner) {
    g_active.fetch_add(1, std::memory_order_acq_rel);
    bool result = false;
    __try {
        AcquireSRWLockShared(&g_lifecycleLock);
        const Gate original = g_handle.original != nullptr
                                  ? reinterpret_cast<Gate>(g_handle.original) : g_target;
        const bool observeCall = g_accepting;
        ReleaseSRWLockShared(&g_lifecycleLock);
        if (original != nullptr) result = original(owner);
        if (observeCall) {
            g_gateOwner.store(reinterpret_cast<std::uintptr_t>(owner), std::memory_order_release);
            observe(owner, result);
        }
    } __finally {
        g_active.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result; // Never force a pass, change a record, or suppress a native call.
}

/** Fresh parent fields, checked before and after the memory walk. Readability is not ownership. */
bool source_matches(const ActivitySource& source) noexcept {
    std::uint64_t sessionId = 0;
    std::array<std::byte, 24> binding{};
    return source.client >= 0x10000 && source.slot >= 0x10000 && source.roster >= 0x10000
           && source.receipt && read(source.client + kEstablishedSessionOffset, &sessionId, sizeof sessionId)
           && sessionId == source.sessionId
           && read(source.client + kSlotOffset, binding.data(), binding.size())
           && field<std::uintptr_t>(binding.data(), 0) == source.slot
           && field<std::uintptr_t>(binding.data(), 8) == source.roster
           && field<std::uint8_t>(binding.data(), 17) == 1;
}

void report_post_load(const Snapshot& out, const char* reason) noexcept {
    std::size_t valid = 0, seeded = 0;
    for (std::size_t i = 0; out.readable && i < out.count; ++i) {
        valid += out.records[i].valid;
        seeded += out.records[i].valid && out.records[i].unseeded == 0;
    }
    std::array<char, 360> line{};
    const auto emit = [&line](int n) {
        if (n > 0 && static_cast<std::size_t>(n) < line.size())
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(n)});
    };
    emit(std::snprintf(line.data(), line.size(),
        "ev=load_validation stage=post_load result=%s reason=%s session=0x%llX generation=%llu "
        "sample_tick=%llu after_fully_enabled_ms=%llu records=%zu valid=%zu seeded=%zu "
        "unseeded=%zu invalid_headers=%zu owner=0x%llX",
        out.readable ? "ok" : "unavailable", reason,
        static_cast<unsigned long long>(out.sessionId),
        static_cast<unsigned long long>(out.activityGeneration),
        static_cast<unsigned long long>(out.tick),
        static_cast<unsigned long long>(out.tick - out.worldReadyTick),
        out.count, valid, seeded, valid - seeded, out.invalidHeaders,
        static_cast<unsigned long long>(out.owner)));
    if (!out.readable) return;
    constexpr std::array<std::uint8_t, 4> types{68, 53, 35, 11};
    for (const auto type : types) {
        const Record* found = nullptr;
        std::size_t matches = 0;
        for (std::size_t i = 0; i < out.count; ++i) {
            const Record& row = out.records[i];
            if (row.valid && row.key == 0x1EB557AD && row.type == type) {
                found = &row;
                ++matches;
            }
        }
        const bool unique = matches == 1;
        emit(std::snprintf(line.data(), line.size(),
            "ev=load_validation stage=controller_post_load sample_tick=%llu type=%u matches=%zu "
            "slot=%d unseeded=%d auth=%08X sense=%08X",
            static_cast<unsigned long long>(out.tick), unsigned(type), matches,
            unique ? int(found->slot) : -1, unique ? int(found->unseeded) : -1,
            unique ? found->authSchema : 0xFFFFFFFFU, unique ? found->senseSchema : 0xFFFFFFFFU));
    }
}

void sample_post_load(std::uint64_t readyTick) noexcept {
    if (!TryAcquireSRWLockExclusive(&g_captureLock)) return;
    // RAII releases the diagnostic scratch lease on every early return. No native call is made.
    struct CaptureLease { ~CaptureLease() { ReleaseSRWLockExclusive(&g_captureLock); } } lease;
    const auto now = GetTickCount64();
    if (now - g_lastPostSample < kPostSampleIntervalMs) return;
    g_lastPostSample = now;
    const auto slice = hooks::bootflow::current_slice_set();
    server::bap::CurrentActivityLinkView link{};
    Snapshot& out = g_sample;
    out = {};
    out.observed = true;
    out.postLoad = true;
    out.tick = now;
    out.worldReadyTick = readyTick;
    const char* reason = "activity_link";
    if (slice.present && server::bap::current_activity_link_view(slice.index, link)
        && link.effectiveRegion == slice.index) {
        out.sessionId = link.binding.sessionId;
        out.activityGeneration = link.activityClientGeneration;
        ActivitySource source{};
        std::size_t matches = 0;
        AcquireSRWLockShared(&g_sourceLock);
        for (const auto& candidate : g_sources) {
            if (candidate.client != 0 && candidate.sessionId == out.sessionId) {
                source = candidate;
                ++matches;
            }
        }
        ReleaseSRWLockShared(&g_sourceLock);
        reason = matches == 0 ? "no_membership_witness" : "ambiguous_membership_witness";
        if (matches == 1) {
            out.owner = source.roster + kSyncOwnerOffset;
            reason = "parent_changed_or_unreadable";
            if (source_matches(source)) {
                reason = "owner_not_witnessed_by_seed_gate";
                if (out.owner == g_gateOwner.load(std::memory_order_acquire)) {
                    capture_pool(out);
                    reason = out.readable ? "none" : "pool_changed_or_unreadable";
                    server::bap::CurrentActivityLinkView after{};
                    if (!source_matches(source)
                        || !server::bap::current_activity_link_view(slice.index, after)
                        || !state::activity::same_binding(link.binding, after.binding)
                        || link.activityClientGeneration != after.activityClientGeneration
                        || after.effectiveRegion != slice.index || !hooks::bootflow::in_world()
                        || g_worldReadyTick.load(std::memory_order_acquire) != readyTick) {
                        out.readable = false;
                        reason = "context_changed_during_read";
                    }
                }
            }
        }
    }
    // A failed post-load check replaces a stale successful snapshot with explicit unknowns.
    AcquireSRWLockExclusive(&g_snapshotLock);
    g_snapshot = out;
    ReleaseSRWLockExclusive(&g_snapshotLock);
    report_post_load(out, reason);
}

bool idle() noexcept { return g_active.load(std::memory_order_acquire) == 0; }
} // namespace

bool install() noexcept {
    AcquireSRWLockExclusive(&g_lifecycleLock);
    if (g_handle.attached) { ReleaseSRWLockExclusive(&g_lifecycleLock); return true; }
    auto* target = patterns::scan_main_image_unique(kSignature, "load_validation_seed_gate");
    g_target = reinterpret_cast<Gate>(target);
    const bool ok = target != nullptr && hooking::detour::install(
        {target, reinterpret_cast<void*>(&seeded_gate)}, g_handle);
    g_accepting = ok;
    g_installed.store(ok, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    core::log::write(core::log::Channel::client,
                     ok ? core::log::Level::info : core::log::Level::warn,
                     ok ? "ev=load_validation stage=install result=ok read_only=1"
                        : "ev=load_validation stage=install result=unavailable");
    return ok;
}

bool uninstall() noexcept {
    AcquireSRWLockExclusive(&g_lifecycleLock);
    g_accepting = false;
    const std::array protectedEntries{
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&seeded_gate)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&poll_post_load)}};
    const bool ok = !g_handle.attached || hooking::detour::uninstall(
        g_handle, protectedEntries, &idle) == hooking::detour::UninstallResult::removed;
    if (ok) g_installed.store(false, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return ok;
}

void snapshot(Snapshot& output, PlayerSnapshot& player) noexcept {
    AcquireSRWLockShared(&g_snapshotLock);
    output = g_snapshot;
    player = g_player;
    ReleaseSRWLockShared(&g_snapshotLock);
    output.installed = g_installed.load(std::memory_order_acquire);
}
void note_player(const hooks::bootflow::spawn::Reading& reading) noexcept {
    AcquireSRWLockExclusive(&g_snapshotLock);
    g_player.reading = reading;
    g_player.readingTick = GetTickCount64();
    ReleaseSRWLockExclusive(&g_snapshotLock);
}
void note_spawn_gate(bool allowed) noexcept {
    AcquireSRWLockExclusive(&g_snapshotLock);
    g_player.gateAllowed = allowed;
    g_player.gateTick = GetTickCount64();
    ReleaseSRWLockExclusive(&g_snapshotLock);
}

void note_activity_client(std::uintptr_t client, std::uint64_t sessionId,
                          std::uintptr_t slot, std::uintptr_t roster, bool receipt) noexcept {
    AcquireSRWLockExclusive(&g_sourceLock);
    ActivitySource* free = nullptr;
    for (auto& source : g_sources) {
        if (source.client == client) { free = &source; break; }
        if (source.client == 0 && free == nullptr) free = &source;
    }
    if (free != nullptr) *free = {client, slot, roster, sessionId, receipt};
    ReleaseSRWLockExclusive(&g_sourceLock);
}

void note_world_transition(std::string_view message) noexcept {
    if (!message.starts_with("world_controller:slice_set_transition_manager: Mode changed from '")) return;
    g_worldReadyTick.store(message.ends_with("to 'fully_enabled'.") ? GetTickCount64() : 0,
                           std::memory_order_release);
}

__declspec(noinline) void poll_post_load() noexcept {
    g_active.fetch_add(1, std::memory_order_acq_rel);
    const auto ready = g_worldReadyTick.load(std::memory_order_acquire);
    if (g_installed.load(std::memory_order_acquire) && ready != 0 && hooks::bootflow::in_world())
        sample_post_load(ready);
    g_active.fetch_sub(1, std::memory_order_acq_rel);
}
} // namespace sunrise::client::diagnostics::load_validation
