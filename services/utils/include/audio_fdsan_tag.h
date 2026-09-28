/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_AUDIO_FDSAN_TAG_H
#define OHOS_AUDIO_FDSAN_TAG_H

#include <cstdint>

constexpr uint64_t FD_SYSTEM_SOUND_AUDIO_URI_TAG =
    (static_cast<uint64_t>(0xD002B80 & 0xFFFFFF) << 32) | 1;
constexpr uint64_t FD_SYSTEM_SOUND_HAPTICS_URI_TAG =
    (static_cast<uint64_t>(0xD002B80 & 0xFFFFFF) << 32) | 2;
constexpr uint64_t FD_SYSTEM_SOUND_CUSTOMIZED_TONE_WRITE_TAG =
    (static_cast<uint64_t>(0xD002B80 & 0xFFFFFF) << 32) | 3;
constexpr uint64_t FD_SYSTEM_SOUND_TONE_OPEN_TAG =
    (static_cast<uint64_t>(0xD002B80 & 0xFFFFFF) << 32) | 4;
constexpr uint64_t FD_SYSTEM_SOUND_LOAD_TAG =
    (static_cast<uint64_t>(0xD002B80 & 0xFFFFFF) << 32) | 5;

constexpr uint64_t FD_AUDIO_HAPTIC_REGISTER_SOURCE_TAG =
    (static_cast<uint64_t>(0xD002B81 & 0xFFFFFF) << 32) | 6;
constexpr uint64_t FD_AUDIO_HAPTIC_AVPLAYER_AUDIO_TAG =
    (static_cast<uint64_t>(0xD002B81 & 0xFFFFFF) << 32) | 7;
constexpr uint64_t FD_AUDIO_HAPTIC_SOUNDPOOL_AUDIO_TAG =
    (static_cast<uint64_t>(0xD002B81 & 0xFFFFFF) << 32) | 8;
constexpr uint64_t FD_AUDIO_HAPTIC_OPEN_HAPTIC_SOURCE_TAG =
    (static_cast<uint64_t>(0xD002B81 & 0xFFFFFF) << 32) | 9;

#endif // OHOS_AUDIO_FDSAN_TAG_H
