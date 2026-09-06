#include "roster_validation.h"

#include <Windows.h>
#include <algorithm>
#include "../internal.h"

namespace sunrise::server::bap::diagnostics::roster_validation {
namespace {
SRWLOCK g_lock = SRWLOCK_INIT;
// No encoder spans escape the stage callback.
std::array<Snapshot, kSessionCount> g_staged{};
std::array<Snapshot, kSessionCount> g_published{};

bool same_identity(const Snapshot& a, const Snapshot& b) noexcept {
    if (!a.valid || !a.complete || !b.complete
        || !state::activity::same_binding(a.binding, b.binding)
        || a.generation != b.generation || a.groupCount != b.groupCount
        || a.recordCount != b.recordCount || a.region != b.region
        || a.hasRegion != b.hasRegion || a.epochFirst != b.epochFirst
        || a.epochSecond != b.epochSecond) {
        return false;
    }
    for (std::size_t i = 0; i < a.groupCount; ++i) {
        if (a.groups[i].key != b.groups[i].key
            || a.groups[i].objectTag != b.groups[i].objectTag
            || a.groups[i].count != b.groups[i].count
            || a.groups[i].sequence != b.groups[i].sequence) return false;
    }
    for (std::size_t i = 0; i < a.recordCount; ++i) {
        if (a.records[i].key != b.records[i].key || a.records[i].slot != b.records[i].slot
            || a.records[i].type != b.records[i].type
            || a.records[i].flags != b.records[i].flags) return false;
    }
    return true;
}
} // namespace

void stage(const Session& session, const message::Snapshot& source,
           std::size_t bytes, std::uint64_t hash) noexcept {
    if (session.id == 0 || session.id > g_staged.size()) return;
    // Only the BAP writer touches staged storage; rendering reads published storage only.
    Snapshot& out = g_staged[session.id - 1];
    out = {};
    out.binding = session.activity.session;
    out.generation = session.activity.bindingGeneration;
    out.stagedTick = GetTickCount64();
    out.identitySince = out.stagedTick;
    out.hash = hash;
    out.bytes = bytes;
    out.region = source.region;
    out.hasRegion = source.hasRegion;
    out.lifetime = source.lifetime;
    out.epochFirst = source.patchEpoch.first;
    out.epochSecond = source.patchEpoch.second;
    out.directorBodies = source.authorDirectorBodies;
    out.wideBodies = source.authorWideRecordBodies;
    out.complete = source.roster.groupCount <= out.groups.size();
    out.groupCount = (std::min)(source.roster.groupCount, out.groups.size());
    for (std::size_t i = 0; i < out.groupCount; ++i) {
        const message::Group& group = source.roster.groups[i];
        out.groups[i] = {group.key, group.objectTag,
                         static_cast<std::uint32_t>(group.slotTypes.size()),
                         group.hasStateSequence ? group.stateSequence : source.stateSequence};
        for (std::size_t slot = 0; slot < group.slotTypes.size(); ++slot) {
            if (out.recordCount == out.records.size()
                || slot >= group.slotIndices.size() || slot >= group.slotFlags.size()) {
                out.complete = false;
                continue;
            }
            out.records[out.recordCount++] = {
                group.key, group.slotIndices[slot], group.slotTypes[slot], group.slotFlags[slot]};
        }
    }
    out.valid = true;
}

void commit(const Session& session) noexcept {
    if (session.id == 0 || session.id > g_staged.size()) return;
    Snapshot& staged = g_staged[session.id - 1];
    if (!staged.valid || staged.generation != session.activity.bindingGeneration
        || !state::activity::same_binding(staged.binding, session.activity.session)) {
        staged.valid = false;
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    Snapshot& published = g_published[session.id - 1];
    if (same_identity(published, staged)) staged.identitySince = published.identitySince;
    staged.publishedTick = GetTickCount64();
    published = staged;
    ReleaseSRWLockExclusive(&g_lock);
    staged.valid = false;
}

void discard(const Session& session) noexcept {
    if (session.id != 0 && session.id <= g_staged.size()) g_staged[session.id - 1].valid = false;
}

bool snapshot(const state::activity::SessionBinding& binding,
              std::uint64_t generation, Snapshot& output) noexcept {
    output = {};
    AcquireSRWLockShared(&g_lock);
    bool found = false;
    for (const Snapshot& entry : g_published) {
        if (entry.valid && entry.generation == generation
            && state::activity::same_binding(entry.binding, binding)) {
            if (found) { output = {}; found = false; break; }
            output = entry;
            found = true;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}
} // namespace sunrise::server::bap::diagnostics::roster_validation
