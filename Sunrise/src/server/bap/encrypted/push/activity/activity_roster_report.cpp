#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <span>

#include "../../../../../core/logging/log.h"
#include "internal.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

/** Log names for each outcome, in the enum's own order. */
constexpr std::array<const char*, 7> kOutcomeNames = {
    "ok", "no_epoch", "no_layout", "no_groups", "no_override_target", "encode", "unchanged"};

/** Package slot type for one scene sensor. */
constexpr std::uint8_t kSceneSensorSlotType = 43;
/** Package slot type for one encounter engagement sensor. */
constexpr std::uint8_t kEngagementSensorSlotType = 70;
/** Package slot type for one authored squad. */
constexpr std::uint8_t kSquadSlotType = 1;

/** Enough for a fresh launch's arrival; never dump an unbounded gameplay stream. */
constexpr unsigned kWireCaptureLimit = 16;
constexpr std::size_t kWireByteLimit = 16 * 1024;
constexpr std::size_t kWireChunkBytes = 128;
std::atomic_uint g_wireCaptures{0};

/** Returns true when the exact slot has a retained Auth body. */
[[nodiscard]] bool has_override(const message::Snapshot& snapshot,
                                const message::Group& group,
                                std::uint8_t slotType,
                                std::uint16_t slotIndex) noexcept {
    for (const message::AuthOverride& value : snapshot.authOverrides) {
        if (value.present && value.objectTag == group.objectTag && value.key == group.key
            && value.slotType == slotType && value.slotIndex == slotIndex) {
            return true;
        }
    }
    return false;
}

/** Returns true when this group owns a retained type-1 Auth body. */
[[nodiscard]] bool owns_squad_override(const message::Snapshot& snapshot,
                                       const message::Group& group) noexcept {
    for (const message::AuthOverride& value : snapshot.authOverrides) {
        if (value.present && value.slotType == kSquadSlotType && value.objectTag == group.objectTag
            && value.key == group.key) {
            return true;
        }
    }
    return false;
}

/** Counts companion Auth slots which reset without a body. */
[[nodiscard]] std::size_t empty_auth_count(const message::Snapshot& snapshot,
                                           std::uint8_t slotType) noexcept {
    std::size_t count = 0;
    for (std::size_t groupIndex = 0; groupIndex < snapshot.roster.groupCount; ++groupIndex) {
        const message::Group& group = snapshot.roster.groups[groupIndex];
        if (!owns_squad_override(snapshot, group)) {
            continue;
        }
        for (std::size_t slot = 0; slot < group.slotTypes.size(); ++slot) {
            if (group.slotTypes[slot] == slotType
                && (group.slotFlags[slot] & message::kSlotAuthFlag) != 0
                && message::auth_body_bits(snapshot, slotType, false) == 0
                && !has_override(snapshot, group, slotType, group.slotIndices[slot])) {
                ++count;
            }
        }
    }
    return count;
}

} // namespace

/** Captures real encoder output, avoiding a second implementation of the slot/body decisions. */
void report_roster_wire(const message::Snapshot& snapshot,
                        std::span<const std::byte> body,
                        std::uint64_t bodyHash) noexcept {
    if (!core::log::accepts(core::log::Channel::server, core::log::Level::debug)) {
        return;
    }
    const unsigned capture = g_wireCaptures.fetch_add(1, std::memory_order_relaxed);
    if (capture >= kWireCaptureLimit) {
        return;
    }
    std::array<char, core::log::kLineCapacity> line{};
    const auto emit = [&line](int written) noexcept {
        if (written > 0 && static_cast<std::size_t>(written) < line.size()) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    };
    const bool complete = body.size() <= kWireByteLimit;
    emit(std::snprintf(line.data(), line.size(),
                       "ev=activity stage=spawn_wire capture=%u result=staged hash=0x%016llX "
                       "bytes=%zu complete=%u epoch=%u/%u player=0x%016llX keygroup=0x%08X "
                       "lifetime=%u has_region=%u region=%u await_sync=%u phase_one_only=%u "
                       "all_player_slots=%u director_bodies=%u wide_bodies=%u",
                       capture, static_cast<unsigned long long>(bodyHash), body.size(),
                       complete ? 1U : 0U, static_cast<unsigned>(snapshot.patchEpoch.first),
                       static_cast<unsigned>(snapshot.patchEpoch.second),
                       static_cast<unsigned long long>(snapshot.playerKey),
                       snapshot.roster.playerKeyGroup, static_cast<unsigned>(snapshot.lifetime),
                       snapshot.hasRegion ? 1U : 0U, snapshot.region,
                       snapshot.awaitClientSync ? 1U : 0U, snapshot.phaseOneOnly ? 1U : 0U,
                       snapshot.keyOnEveryParticipationSlot ? 1U : 0U,
                       snapshot.authorDirectorBodies ? 1U : 0U,
                       snapshot.authorWideRecordBodies ? 1U : 0U));
    // Refuse oversized captures explicitly instead of presenting a prefix as a complete packet.
    if (!complete) {
        return;
    }
    constexpr char hexDigits[] = "0123456789ABCDEF";
    for (std::size_t offset = 0; offset < body.size(); offset += kWireChunkBytes) {
        const std::size_t count = body.size() - offset < kWireChunkBytes
                                     ? body.size() - offset : kWireChunkBytes;
        std::array<char, kWireChunkBytes * 2 + 1> hex{};
        for (std::size_t index = 0; index < count; ++index) {
            const unsigned value = std::to_integer<unsigned>(body[offset + index]);
            hex[index * 2] = hexDigits[value >> 4];
            hex[index * 2 + 1] = hexDigits[value & 15U];
        }
        emit(std::snprintf(line.data(), line.size(),
                           "ev=activity stage=spawn_wire_bytes capture=%u offset=%zu count=%zu hex=%s",
                           capture, offset, count, hex.data()));
    }
    emit(std::snprintf(line.data(), line.size(),
                       "ev=activity stage=spawn_wire_end capture=%u bytes=%zu hash=0x%016llX",
                       capture, body.size(), static_cast<unsigned long long>(bodyHash)));
}

/** Reports one roster push, and only when its outcome is new. */
void report_roster_push(Session& session,
                        const message::Snapshot& snapshot,
                        std::string_view destination,
                        std::size_t bytes,
                        std::int32_t grant,
                        RosterOutcome outcome,
                        std::uint64_t bodyHash,
                        std::uint8_t forced) noexcept {
    const message::Roster& roster = snapshot.roster;
    const auto reason = static_cast<std::uint8_t>(outcome) + 1U;
    // A published push reports every time. A refusal reports only when its reason is new.
    if (outcome != RosterOutcome::published && session.activityRosterReason == reason) {
        return;
    }
    session.activityRosterReason = static_cast<std::uint8_t>(reason);
    std::size_t slots = 0;
    for (std::size_t index = 0; index < roster.groupCount; ++index) {
        slots += roster.groups[index].slotTypes.size();
    }
    // The per-bubble half is reported on its own. A body carrying it and one that does not are
    // otherwise the same line, and the group count alone cannot tell them apart.
    std::size_t bubbleKeys = 0;
    for (const message::BubbleSubBlock& block : roster.bubbleSubBlocks) {
        bubbleKeys += block.keys.size();
    }
    std::int32_t overrideState = -1;
    std::int32_t firstAuthType = -1;
    std::int32_t firstAuthSlot = -1;
    std::int32_t lastAuthType = -1;
    std::int32_t lastAuthSlot = -1;
    std::uint32_t firstAuthObject = 0;
    std::uint32_t firstAuthKey = 0;
    std::uint32_t lastAuthObject = 0;
    std::uint32_t lastAuthKey = 0;
    const message::AuthOverride* firstAuth = nullptr;
    const message::AuthOverride* lastAuth = nullptr;
    for (const message::AuthOverride& value : snapshot.authOverrides) {
        if (value.present && value.slotType == kSquadSlotType) {
            if (firstAuth == nullptr) {
                firstAuth = &value;
            }
            lastAuth = &value;
        }
    }
    if (firstAuth != nullptr && lastAuth != nullptr) {
        firstAuthType = firstAuth->slotType;
        firstAuthSlot = firstAuth->slotIndex;
        firstAuthObject = firstAuth->objectTag;
        firstAuthKey = firstAuth->key;
        lastAuthType = lastAuth->slotType;
        lastAuthSlot = lastAuth->slotIndex;
        lastAuthObject = lastAuth->objectTag;
        lastAuthKey = lastAuth->key;
        for (std::size_t index = 0; index < roster.groupCount; ++index) {
            const message::Group& group = roster.groups[index];
            if (group.objectTag == firstAuthObject && group.key == firstAuthKey) {
                overrideState =
                    group.hasStateSequence ? group.stateSequence : snapshot.stateSequence;
                break;
            }
        }
    }
    const std::size_t emptySceneAuth = empty_auth_count(snapshot, kSceneSensorSlotType);
    const std::size_t emptyEngagementAuth = empty_auth_count(snapshot, kEngagementSensorSlotType);
    const state::activity::membership::ClientPlacement placement =
        client_placement(session, nullptr);
    std::array<char, core::log::kLineCapacity> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=activity stage=roster result=%s soid=0x%llX public=%u dest=%.*s "
                      "groups=%zu top=%zu sub=%zu subkeys=%zu objects=%zu bytes=%zu state=%u "
                      "auth=%zu authstate=%d authfirst=%d:%d:0x%X:0x%X "
                      "authlast=%d:%d:0x%X:0x%X "
                      "sceneempty=%zu engageempty=%zu "
                      "keygroup=0x%X grant=%d region=%u slice=%u spawn=0x%X join=0x%llX "
                      "player=0x%llX pending_region=%d current_region=%d client_bubble=%d held=%d "
                      "entered=%d selected=%d hash=0x%016llX force=0x%02X",
                      kOutcomeNames[static_cast<std::size_t>(outcome)],
                      static_cast<unsigned long long>(session.activity.session.sessionId),
                      session.activity.role == ActivityClientRole::publicTarget ? 1U : 0U,
                      static_cast<int>(destination.size()),
                      destination.data(),
                      roster.groupCount,
                      roster.topLevelGroupCount,
                      roster.bubbleSubBlocks.size(),
                      bubbleKeys,
                      slots,
                      bytes,
                      session.activityRosterState,
                      snapshot.authOverrides.size(),
                      overrideState,
                      firstAuthType,
                      firstAuthSlot,
                      firstAuthObject,
                      firstAuthKey,
                      lastAuthType,
                      lastAuthSlot,
                      lastAuthObject,
                      lastAuthKey,
                      emptySceneAuth,
                      emptyEngagementAuth,
                      roster.playerKeyGroup,
                      grant,
                      snapshot.region,
                      snapshot.spawnSliceSet,
                      snapshot.spawnSetHash,
                      static_cast<unsigned long long>(session.activityCharacterSoid),
                      static_cast<unsigned long long>(snapshot.playerKey),
                      placement.region,
                      placement.currentRegion,
                      placement.bubble,
                      state::activity::membership::instantiated_region(placement),
                      placement.entered ? 1 : 0,
                      session.activityMissionSeed.scriptSelected ? 1 : 0,
                      static_cast<unsigned long long>(bodyHash),
                      static_cast<unsigned>(forced));
    if (written > 0) {
        // A skipped unchanged body is normal steady state, not a refusal worth a warning.
        const bool quiet =
            outcome == RosterOutcome::published || outcome == RosterOutcome::unchanged;
        core::log::write(core::log::Channel::server,
                         quiet ? core::log::Level::debug : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    if (outcome != RosterOutcome::published) {
        return;
    }
    // One line per typed body and one per group revision, so two published bodies with
    // different hashes can be told apart by the part that moved.
    for (std::size_t index = 0; index < roster.groupCount; ++index) {
        const message::Group& group = roster.groups[index];
        const int groupWritten =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=roster_group key=0x%08X seq=%u has_seq=%u "
                          "object=0x%08X slots=%zu mission_seed_only=%u",
                          group.key,
                          static_cast<unsigned>(group.stateSequence),
                          group.hasStateSequence ? 1U : 0U,
                          group.objectTag, group.slotTypes.size(), group.missionSeedOnly ? 1U : 0U);
        if (groupWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(groupWritten)});
        }
    }
    for (const message::BubbleSubBlock& block : roster.bubbleSubBlocks) {
        for (const std::uint32_t key : block.keys) {
            const int keyWritten =
                std::snprintf(line.data(),
                              line.size(),
                              "ev=activity stage=roster_key bubble=%u key=0x%08X",
                              static_cast<unsigned>(block.bubble),
                              key);
            if (keyWritten > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::debug,
                                 {line.data(), static_cast<std::size_t>(keyWritten)});
            }
        }
    }
    for (const message::AuthOverride& value : snapshot.authOverrides) {
        if (!value.present) {
            continue;
        }
        const std::span<const std::byte> body(value.body.data(), value.byteCount);
        const int authWritten =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=roster_auth type=%u slot=%u key=0x%08X bits=%u "
                          "hash=0x%016llX",
                          static_cast<unsigned>(value.slotType),
                          static_cast<unsigned>(value.slotIndex),
                          value.key,
                          static_cast<unsigned>(value.bitCount),
                          static_cast<unsigned long long>(body_hash(body)));
        if (authWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(authWritten)});
        }
    }
}

} // namespace sunrise::server::bap::encrypted::push::activity
