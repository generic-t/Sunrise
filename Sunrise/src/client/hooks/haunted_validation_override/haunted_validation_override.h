#pragma once

namespace sunrise::client::hooks::haunted_validation_override {

/** Installs the narrow Haunted descriptor-validation override. */
[[nodiscard]] bool install() noexcept;

/** Restores the game's validation instruction and removes the override. */
[[nodiscard]] bool uninstall() noexcept;

} // namespace sunrise::client::hooks::haunted_validation_override
