/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETAKEYS_H
#define MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETAKEYS_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Key for track index, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_TRACK_INDEX;

/**
 * @brief Key for track type, value type is int32_t
 * @since 23
 */
extern const char* OH_AVMETA_KEY_TRACK_TYPE;

/**
 * @brief Key for codec mime type, value type is string.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_MIME_TYPE;

/**
 * @brief Key for duration, value type is int64_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_DURATION;

/**
 * @brief Key for bitrate, value type is uint32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_BITRATE;

/**
 * @brief Key for video frame rate (frame count in 100s), value type is double.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_FRAME_RATE;

/**
 * @brief Key for video width, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_WIDTH;

/**
 * @brief Key for video height, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_HEIGHT;

/**
 * @brief Key for audio channel count, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_CHANNEL_COUNT;

/**
 * @brief Key for audio sample rate (Hz), value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_SAMPLE_RATE;

/**
 * @brief Key for audio bit depth, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_SAMPLE_DEPTH;

/**
 * @brief Key for language. value type is string.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_LANGUAGE;

/**
 * @brief Key for track name, value type is string.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_TRACK_NAME;

/**
 * @brief Key for hdr type, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_HDR_TYPE;

/**
 * @brief Key for is original width, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_ORIGINAL_WIDTH;

/**
 * @brief Key for is original height, value type is int32_t.
 * @since 23
 */
extern const char* OH_AVMETA_KEY_ORIGINAL_HEIGHT;

/**
 * @brief Key to get the list of referenced track IDs. Only used by metadata extractor.
 * @since 23
 */
extern const char* OH_AVMETADATA_EXTRACTOR_REF_TRACK_IDS;

/**
 * @brief Key to get the track reference type. Only used by metadata extractor.
 * @since 23
 */
extern const char* OH_AVMETADATA_EXTRACTOR_TRACK_REF_TYPE;

#ifdef __cplusplus
}
#endif

#endif // MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETAKEYS_H
