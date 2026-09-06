#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include "../hooks/bootflow/spawn/probe.h"

namespace sunrise::client::diagnostics::load_validation {

inline constexpr std::size_t kRecordCapacity = 4096;
struct Record final {
    std::uint32_t key{}, senseSchema{}, authSchema{}, bubble{};
    std::uint16_t slot{};
    std::uint8_t type{}, unseeded{};
    bool valid{};
};

/** Last labelled sample: either a borrowed seed-gate owner or a revalidated post-load read. */
struct Snapshot final {
    std::array<Record, kRecordCapacity> records{};
    std::uintptr_t owner{};
    std::uint64_t tick{};
    std::uint64_t sessionId{}, activityGeneration{}, worldReadyTick{};
    std::size_t count{}, invalidHeaders{};
    bool installed{}, observed{}, readable{}, nativeGatePassed{}, postLoad{};
};

struct PlayerSnapshot final {
    hooks::bootflow::spawn::Reading reading{};
    std::uint64_t readingTick{}, gateTick{};
    bool gateAllowed{};
};

/** Optional observational hook: a missing signature does not disable networking. */
[[nodiscard]] bool install() noexcept;
[[nodiscard]] bool uninstall() noexcept;
void snapshot(Snapshot& output, PlayerSnapshot& player) noexcept;
/** Called only from existing spawn-gate observations; neither reruns a native accessor. */
void note_player(const hooks::bootflow::spawn::Reading& reading) noexcept;
void note_spawn_gate(bool allowed) noexcept;
/** Value-only witnesses from existing hooks. No extra native calls or hook installation. */
void note_activity_client(std::uintptr_t client, std::uint64_t sessionId,
                          std::uintptr_t slot, std::uintptr_t roster, bool receipt) noexcept;
void note_world_transition(std::string_view message) noexcept;
/** Guarded memory snapshots after fully_enabled, from the existing game-frame callback. */
void poll_post_load() noexcept;

} // namespace sunrise::client::diagnostics::load_validation
