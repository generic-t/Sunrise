#include "ui_hud_load_validation_overlay.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <tuple>
#include <imgui.h>
#include "../../../../client/diagnostics/load_validation.h"
#include "../../../../client/hooks/bootflow/bootflow_hook_lifecycle.h"
#include "../../../../client/hooks/world_objects/world_object_registry.h"
#include "../../../../server/bap/diagnostics/roster_validation.h"
#include "../../../../server/bap/runtime.h"
#include "../../../../server/activity/mission/mission_script_runtime.h"
#include "../../../logging/log.h"

namespace sunrise::core::ui::hud::overlays::load_validation {
namespace {
namespace wire = server::bap::diagnostics::roster_validation;
namespace native = client::diagnostics::load_validation;
namespace boot = client::hooks::bootflow;
namespace host = server::activity::host;
namespace mission = server::activity::mission;
constexpr ImVec4 kGood{0.40F, 0.92F, 0.58F, 1.0F};
constexpr ImVec4 kWait{1.0F, 0.78F, 0.30F, 1.0F};
constexpr ImVec4 kBad{1.0F, 0.40F, 0.40F, 1.0F};
constexpr std::uint32_t kControllerRegistry = 0x1EB557AD;
constexpr std::array<std::uint8_t, 4> kControllerTypes{68, 53, 35, 11};

struct Counts { std::size_t expected{}, registered{}, seeded{}, ambiguous{}; };
struct Match { const native::Record* record{}; bool ambiguous{}; };
wire::Snapshot g_wire{};
native::Snapshot g_native{};
native::PlayerSnapshot g_player{};
server::bap::CurrentActivityLinkView g_link{};
host::InstanceSnapshot g_host{};
mission::DiagnosticsSnapshot g_missions{};
std::array<const native::Record*, native::kRecordCapacity> g_index{};
std::array<Match, wire::kRecordCapacity> g_matches{};
std::array<Counts, wire::message::kPublishedGroupCapacity> g_groups{};
std::array<Counts, 128> g_types{};
Counts g_total{};
std::uint64_t g_refreshed{};
bool g_hasLink{}, g_hasWire{}, g_hasHost{}, g_canCompare{};

auto identity(const native::Record& row) noexcept { return std::tuple{row.key, row.type, row.slot}; }

void refresh(std::uint64_t now) noexcept {
    if (g_refreshed != 0 && now - g_refreshed < 250) return;
    g_refreshed = now;
    const boot::CurrentSliceSet slice = boot::current_slice_set();
    g_hasLink = server::bap::current_activity_link_view(slice.present ? slice.index : -1, g_link);
    g_hasWire = g_hasLink && wire::snapshot(g_link.binding, g_link.activityClientGeneration, g_wire);
    if (!g_hasWire) g_wire = {};
    g_hasHost = g_hasLink && host::instance_snapshot(g_link.binding, g_host);
    mission::snapshot(g_missions);
    native::snapshot(g_native, g_player);
    g_matches = {};
    g_groups = {};
    g_types = {};
    g_total = {};
    g_canCompare = g_hasWire && g_wire.complete && g_native.installed
                   && g_native.observed && g_native.readable
                   && g_native.tick >= g_wire.identitySince
                   && (!g_native.postLoad || (g_native.sessionId == g_link.binding.sessionId
                       && g_native.activityGeneration == g_link.activityClientGeneration));
    std::size_t nativeCount = 0;
    if (g_canCompare) {
        for (std::size_t i = 0; i < g_native.count; ++i)
            if (g_native.records[i].valid) g_index[nativeCount++] = &g_native.records[i];
        std::sort(g_index.begin(), g_index.begin() + nativeCount,
                  [](const auto* a, const auto* b) { return identity(*a) < identity(*b); });
    }
    for (std::size_t i = 0; i < g_wire.recordCount; ++i) {
        const wire::Record& row = g_wire.records[i];
        Match& match = g_matches[i];
        if (g_canCompare) {
            const auto key = std::tuple{row.key, row.type, row.slot};
            const auto end = g_index.begin() + nativeCount;
            const auto found = std::lower_bound(g_index.begin(), end, key,
                [](const auto* a, const auto& b) { return identity(*a) < b; });
            if (found != end && identity(**found) == key) {
                match.ambiguous = found + 1 != end && identity(**(found + 1)) == key;
                if (!match.ambiguous) match.record = *found;
            }
        }
        const auto count = [&match](Counts& target) {
            ++target.expected;
            target.registered += match.record != nullptr;
            target.seeded += match.record != nullptr && match.record->unseeded == 0;
            target.ambiguous += match.ambiguous;
        };
        count(g_total);
        if (row.type < g_types.size()) count(g_types[row.type]);
        for (std::size_t group = 0; group < g_wire.groupCount; ++group)
            if (g_wire.groups[group].key == row.key) { count(g_groups[group]); break; }
    }
    // A compact retained counterpart to the on-screen totals, only when totals/identity change.
    static std::uint64_t lastIdentity{};
    static Counts last{};
    static bool lastCompared{};
    if (g_hasWire && (lastIdentity != g_wire.identitySince || lastCompared != g_canCompare
        || last.registered != g_total.registered || last.seeded != g_total.seeded
        || last.ambiguous != g_total.ambiguous)) {
        std::array<char, 240> line{};
        const int n = std::snprintf(line.data(), line.size(),
            "ev=load_validation stage=hud published=%zu comparable=%u registered=%zu seeded=%zu "
            "ambiguous=%zu sample_age_ms=%llu",
            g_total.expected, g_canCompare ? 1U : 0U, g_total.registered, g_total.seeded,
            g_total.ambiguous,
            static_cast<unsigned long long>(g_native.observed ? now - g_native.tick : 0));
        if (n > 0 && static_cast<std::size_t>(n) < line.size())
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(n)});
        for (std::size_t i = 0; i < g_wire.recordCount; ++i) {
            const auto& expected = g_wire.records[i];
            if (expected.key != kControllerRegistry
                || std::find(kControllerTypes.begin(), kControllerTypes.end(), expected.type)
                       == kControllerTypes.end()) continue;
            const Match& match = g_matches[i];
            const auto* row = match.record;
            const int detail = std::snprintf(line.data(), line.size(),
                "ev=load_validation stage=controller type=%u slot=%u comparable=%u registered=%u "
                "ambiguous=%u unseeded=%d auth=%08X sense=%08X",
                unsigned(expected.type), unsigned(expected.slot), g_canCompare ? 1U : 0U,
                row != nullptr ? 1U : 0U, match.ambiguous ? 1U : 0U,
                row != nullptr ? int(row->unseeded) : -1,
                row != nullptr ? row->authSchema : 0xFFFFFFFFU,
                row != nullptr ? row->senseSchema : 0xFFFFFFFFU);
            if (detail > 0 && static_cast<std::size_t>(detail) < line.size())
                core::log::write(core::log::Channel::client, core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(detail)});
        }
        lastIdentity = g_wire.identitySince;
        last = g_total;
        lastCompared = g_canCompare;
    }
}

void controllers() noexcept {
    ImGui::Separator();
    ImGui::Text("CONTROLLERS  %08X", kControllerRegistry);
    if (!ImGui::BeginTable("load_validation_controllers", 6,
                           ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody))
        return;
    ImGui::TableSetupColumn("TYPE");
    ImGui::TableSetupColumn("SLOT");
    ImGui::TableSetupColumn("PUB");
    ImGui::TableSetupColumn("NATIVE");
    ImGui::TableSetupColumn("SEED");
    ImGui::TableSetupColumn("AUTH / SENSE");
    ImGui::TableHeadersRow();
    for (const std::uint8_t type : kControllerTypes) {
        const wire::Record* expected = nullptr;
        const Match* match = nullptr;
        for (std::size_t i = 0; i < g_wire.recordCount; ++i) {
            const wire::Record& row = g_wire.records[i];
            if (row.key != kControllerRegistry || row.type != type) continue;
            expected = &row;
            match = &g_matches[i];
            break;
        }
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%u", unsigned(type));
        ImGui::TableNextColumn(); ImGui::Text(expected ? "%u" : "-", expected ? unsigned(expected->slot) : 0U);
        ImGui::TableNextColumn(); ImGui::TextColored(expected ? kGood : kWait, expected ? "Y" : "-");
        const bool nativePresent = match != nullptr && match->record != nullptr;
        const bool seeded = nativePresent && match->record->unseeded == 0;
        ImGui::TableNextColumn();
        ImGui::TextColored(!g_canCompare ? kWait : nativePresent ? kGood : kBad,
                           !g_canCompare ? "?" : nativePresent ? "Y" : "N");
        ImGui::TableNextColumn();
        ImGui::TextColored(!g_canCompare || !nativePresent ? kWait : seeded ? kGood : kBad,
                           !g_canCompare || !nativePresent ? "?" : seeded ? "Y" : "N");
        ImGui::TableNextColumn();
        if (nativePresent) {
            ImGui::Text("%08X / %08X", match->record->authSchema, match->record->senseSchema);
        } else {
            ImGui::TextDisabled("-");
        }
    }
    ImGui::EndTable();
}

void metric(std::size_t value) noexcept {
    if (g_canCompare) ImGui::Text("%zu", value);
    else ImGui::TextDisabled("-");
}

void downstream() noexcept {
    ImGui::Separator();
    ImGui::TextUnformatted("DOWNSTREAM");
    if (g_hasHost) {
        ImGui::Text("HOST  %s  L%u  S%u  R%llu/%llu  P%s",
            g_host.active ? "active" : "inactive", unsigned(g_host.lifetimeState), g_host.senseCount,
            static_cast<unsigned long long>(g_host.stateRevision),
            static_cast<unsigned long long>(g_host.transportRevision), g_host.outputPending ? "Y" : "N");
    } else ImGui::TextDisabled("HOST  -");
    bool found = false;
    if (g_hasLink) {
        for (std::size_t i = 0; i < g_missions.instanceCount; ++i) {
            const auto& instance = g_missions.instances[i];
            if (!state::activity::same_binding(instance.binding, g_link.binding)) continue;
            found = true;
            ImGui::TextColored(instance.vmFaulted ? kBad : kWait,
                "MISSION  %s  start:%s  P%u  VM:%s",
                instance.programStatus.data(), instance.missionStarted ? "yes" : "no",
                instance.phase, instance.vmFaulted ? "FAULT" : instance.vmActive ? "active" : "idle");
            ImGui::Text("  E%llu/%llu  I%llu",
                static_cast<unsigned long long>(instance.eventsCommitted),
                static_cast<unsigned long long>(instance.eventsSeen),
                static_cast<unsigned long long>(instance.intentsTransportStaged));
        }
    }
    if (!found) ImGui::TextDisabled("MISSION  %s", !g_missions.enabled ? "off" : "-");
    const auto objects = client::hooks::world_objects::diagnostics();
    if (objects.installed)
        ImGui::Text("OBJECTS  %zu  O%llu", objects.liveCount,
                    static_cast<unsigned long long>(objects.overflowCount));
    else ImGui::TextDisabled("OBJECTS  -");
}
} // namespace

void draw() noexcept {
    const auto now = GetTickCount64();
    refresh(now);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5.0F, 2.0F));
    const bool inWorld = boot::in_world();
    ImGui::TextColored(inWorld ? kGood : kWait, "LOAD  %s", inWorld ? "READY" : "LOADING");
    if (g_hasLink) {
        const auto& destination = g_link.binding.destination;
        ImGui::Text("%.*s  A%d  R%d",
            int(destination.packageNameLength), reinterpret_cast<const char*>(destination.packageName.data()),
            int(destination.activityIndex), g_link.effectiveRegion);
    } else ImGui::TextDisabled("ACTIVITY  -");
    const auto slice = boot::current_slice_set();
    if (slice.available && slice.present) ImGui::Text("BUBBLE %d  SLICE %d", slice.index / 8, slice.index);
    else ImGui::TextDisabled("BUBBLE / SLICE  -");
    if (g_hasWire && g_player.gateTick >= g_wire.identitySince && g_player.gateTick != 0)
        ImGui::TextColored(g_player.gateAllowed ? kGood : kBad, "GATE  %s  %.1fs",
            g_player.gateAllowed ? "allowed" : "blocked", double(now - g_player.gateTick) / 1000.0);
    else ImGui::TextDisabled("GATE  -");
    if (g_hasWire && g_player.readingTick >= g_wire.identitySince && g_player.readingTick != 0)
        ImGui::Text("PLAYER  rec:%s  +8:%u +10:%u  L%d  %.1fs",
            g_player.reading.hasRecord ? "present" : "absent", unsigned(g_player.reading.recordTask9),
            unsigned(g_player.reading.recordReady), g_player.reading.lifetimeState,
            double(now - g_player.readingTick) / 1000.0);
    else ImGui::TextDisabled("PLAYER  -");
    ImGui::Separator();
    if (!g_hasWire) {
        ImGui::TextDisabled("ROSTER  -");
        downstream();
        ImGui::PopStyleVar();
        return;
    }
    ImGui::Text("ROSTER  %zuG  %zuR  %zuB  %.1fs",
        g_wire.groupCount, g_total.expected, g_wire.bytes, double(now - g_wire.publishedTick) / 1000.0);
    ImGui::Text("EPOCH  %llu/%llu  L%u  BODY D:%s W:%s",
        static_cast<unsigned long long>(g_wire.epochFirst), static_cast<unsigned long long>(g_wire.epochSecond),
        unsigned(g_wire.lifetime), g_wire.directorBodies ? "ON" : "OFF", g_wire.wideBodies ? "ON" : "OFF");
    if (!g_wire.complete) ImGui::TextColored(kBad, "ROSTER  INCOMPLETE");
    if (!g_native.installed) ImGui::TextDisabled("NATIVE  -");
    else if (!g_native.observed) ImGui::TextDisabled("NATIVE  WAIT");
    else {
        ImGui::TextColored(g_native.readable ? kGood : kBad, "NATIVE  %s  %zuR  %.1fs  %s",
            g_native.readable ? "readable" : "unavailable/changed", g_native.count,
            double(now - g_native.tick) / 1000.0, g_native.postLoad ? "POST" : "GATE");
        if (g_native.postLoad) {
            ImGui::Text("  POST  BAD %zu  OWNER %llX", g_native.invalidHeaders,
                static_cast<unsigned long long>(g_native.owner));
        } else {
            ImGui::Text("  GATE %s  BAD %zu  OWNER %llX", g_native.nativeGatePassed ? "Y" : "N",
                g_native.invalidHeaders, static_cast<unsigned long long>(g_native.owner));
        }
    }
    if (ImGui::BeginTable("load_validation_totals", 5,
                          ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody)) {
        ImGui::TableSetupColumn("TARGET"); ImGui::TableSetupColumn("REG");
        ImGui::TableSetupColumn("SEED"); ImGui::TableSetupColumn("MISS"); ImGui::TableSetupColumn("AGE");
        ImGui::TableHeadersRow();
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%zu", g_total.expected);
        ImGui::TableNextColumn(); metric(g_total.registered);
        ImGui::TableNextColumn(); metric(g_total.seeded);
        ImGui::TableNextColumn();
        if (g_canCompare) ImGui::Text("%zu", g_total.expected - g_total.registered);
        else ImGui::TextDisabled("-");
        ImGui::TableNextColumn(); ImGui::Text("%.1fs", double(now - g_native.tick) / 1000.0);
        ImGui::EndTable();
    }
    controllers();
    if (ImGui::TreeNodeEx("GROUPS", ImGuiTreeNodeFlags_SpanAvailWidth)) {
        if (ImGui::BeginTable("load_validation_groups", 5,
                              ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody)) {
            ImGui::TableSetupColumn("KEY"); ImGui::TableSetupColumn("TAG");
            ImGui::TableSetupColumn("REV"); ImGui::TableSetupColumn("R"); ImGui::TableSetupColumn("S");
            ImGui::TableHeadersRow();
            for (std::size_t i = 0; i < g_wire.groupCount; ++i) {
                const auto& group = g_wire.groups[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%08X", group.key);
                ImGui::TableNextColumn(); ImGui::Text("%08X", group.objectTag);
                ImGui::TableNextColumn(); ImGui::Text("%u", unsigned(group.sequence));
                ImGui::TableNextColumn(); metric(g_groups[i].registered);
                ImGui::TableNextColumn(); metric(g_groups[i].seeded);
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }
    if (ImGui::TreeNodeEx("TYPES", ImGuiTreeNodeFlags_SpanAvailWidth)) {
    if (ImGui::BeginTable("load_validation_types", 4,
                          ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody)) {
        ImGui::TableSetupColumn("TYPE"); ImGui::TableSetupColumn("TARGET");
        ImGui::TableSetupColumn("REG"); ImGui::TableSetupColumn("SEED");
        ImGui::TableHeadersRow();
        for (std::size_t type = 0; type < g_types.size(); ++type) {
            if (g_types[type].expected == 0) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%zu", type);
            ImGui::TableNextColumn(); ImGui::Text("%zu", g_types[type].expected);
            ImGui::TableNextColumn(); metric(g_types[type].registered);
            ImGui::TableNextColumn(); metric(g_types[type].seeded);
        }
        ImGui::EndTable();
    }
    ImGui::TreePop();
    }
    downstream();
    ImGui::PopStyleVar();
}
} // namespace sunrise::core::ui::hud::overlays::load_validation
