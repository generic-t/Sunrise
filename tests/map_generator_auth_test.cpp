#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>

#include "core/logging/log.h"
#include "middleware/bap/activity_message/sensor_auth_update.h"
#include "middleware/encoding/bit_reader.h"

namespace sunrise::core::log {
bool accepts(Channel, Level) noexcept { return false; }
void write(Channel, Level, std::string_view) noexcept {}
}

namespace bits = sunrise::middleware::encoding::bits;
namespace auth = sunrise::middleware::bap::activity_message::sensor_auth_update;

static std::uint64_t take(bits::Reader& reader, std::uint8_t width) {
    std::uint64_t value{};
    assert(reader.read(width, value));
    return value;
}

// Independent wire walk of the empty native 86657 map-generator body. The trailing
// schemas 0x8080956C and 0x8080954D have array lengths 32 and 64, not scalar u8s.
static void empty_generator(bits::Reader& reader) {
    for (int side = 0; side < 2; ++side) {
        assert(take(reader, 32) == 0);
        assert(take(reader, 8) == 0);
        for (int anchor = 0; anchor < 4; ++anchor) {
            assert(take(reader, 8) == 0);
            assert(take(reader, 8) == 0);
            assert(take(reader, 32) == 0);
            assert(take(reader, 1) == 0);
        }
        assert(take(reader, 7) == 0);
        assert(take(reader, 1) == 0);
        assert(take(reader, 32) == 0);
        assert(take(reader, 32) == 0);
        for (int field = 0; field < 5; ++field) assert(take(reader, 32) == 0);
        assert(take(reader, 7) == 0); // Dynamic array count; no elements follow.
    }
    assert(take(reader, 32) == 0);
    for (int element = 0; element < 32; ++element) assert(take(reader, 8) == 0);
    for (int element = 0; element < 64; ++element) assert(take(reader, 8) == 0);
}

int main() {
    std::array<std::byte, 512> output{};
    bits::Writer writer(output);
    auth::Snapshot snapshot{};
    snapshot.authorWideRecordBodies = true;
    constexpr std::uint32_t key = 0x34D23982;
    assert(auth::write_object_block(writer, snapshot, 0x8155213E, key, 37, 81,
                                   auth::kSlotAuthFlag | auth::kSlotSenseFlag, false, false));
    // A following nonzero field must not be consumed as part of the generator.
    assert(writer.write(0xA5B6C7D8, 32));
    std::size_t written{};
    assert(writer.finish(written));
    bits::Reader reader(std::span(output).first(written));
    assert(take(reader, auth::kPresenceWidth) == 1);
    assert(take(reader, auth::kKeyWidth) == key);
    assert(take(reader, auth::kSlotTypeWidth) == 37 + auth::kSlotTypeBias);
    assert(take(reader, auth::kSlotIndexWidth) == 81 + auth::kSlotIndexBias);
    assert(take(reader, auth::kKeyWidth) == 1753); // Reset, root, body, absent sense.
    assert(take(reader, 1) == 1);
    assert(take(reader, 1) == 1);
    empty_generator(reader);
    assert(take(reader, 1) == 0);
    assert(take(reader, 32) == 0xA5B6C7D8);
    assert(reader.remaining_bits() < 8);

    // The old 998-bit buffer must be refused, rather than reported as a complete body.
    std::array<std::byte, 125> shortOutput{};
    bits::Writer shortWriter(shortOutput);
    assert(!auth::write_auth_body(shortWriter, snapshot, 37, false));
    std::puts("map generator fixed arrays and following-field alignment passed");
}
