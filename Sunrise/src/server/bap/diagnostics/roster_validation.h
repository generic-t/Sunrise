#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../middleware/bap/activity_message/sensor_auth_update.h"
#include "../../../state/activity/definition.h"

namespace sunrise::server::bap { struct Session; }

namespace sunrise::server::bap::diagnostics::roster_validation {

inline constexpr std::size_t kRecordCapacity = 4096;
namespace message = middleware::bap::activity_message::sensor_auth_update;

struct Record final {
    std::uint32_t key{};
    std::uint16_t slot{};
    std::uint8_t type{};
    std::uint8_t flags{};
};

struct Group final {
    std::uint32_t key{};
    std::uint32_t objectTag{};
    std::uint32_t count{};
    std::uint8_t sequence{};
};

/** Owned copy of an encoded roster, promoted only at the existing transport commit. */
struct Snapshot final {
    state::activity::SessionBinding binding{};
    std::array<Group, message::kPublishedGroupCapacity> groups{};
    std::array<Record, kRecordCapacity> records{};
    std::uint64_t generation{};
    std::uint64_t stagedTick{};
    std::uint64_t publishedTick{};
    std::uint64_t identitySince{};
    std::uint64_t hash{};
    std::size_t bytes{};
    std::size_t groupCount{};
    std::size_t recordCount{};
    std::uint32_t region{};
    std::uint64_t epochFirst{}, epochSecond{};
    std::uint8_t lifetime{};
    bool hasRegion{}, directorBodies{}, wideBodies{}, complete{}, valid{};
};

// Writers run under the existing BAP lock. These never change protocol/session state.
void stage(const Session& session, const message::Snapshot& source,
           std::size_t bytes, std::uint64_t hash) noexcept;
void commit(const Session& session) noexcept;
void discard(const Session& session) noexcept;
/** Copies only the exact selected connection generation; no newest-session fallback. */
[[nodiscard]] bool snapshot(const state::activity::SessionBinding& binding,
                            std::uint64_t generation, Snapshot& output) noexcept;

} // namespace sunrise::server::bap::diagnostics::roster_validation
