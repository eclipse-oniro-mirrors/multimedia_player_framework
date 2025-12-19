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

#include "media_dfx.h"
#include "media_log.h"
#include "avmetakeys.h"
#include "native_avcodec_base.h"

namespace {
    [[maybe_unused]] constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "NativeMetaKeys" };
}

using namespace OHOS;
using namespace OHOS::Media;

const char* OH_AVMETA_KEY_TRACK_INDEX = "track_index";
const char* OH_AVMETA_KEY_TRACK_TYPE = "track_type";
const char* OH_AVMETA_KEY_MIME_TYPE = "codec_mime";
const char* OH_AVMETA_KEY_DURATION = "duration";
const char* OH_AVMETA_KEY_BITRATE = "bitrate";
const char* OH_AVMETA_KEY_FRAME_RATE = "frame_rate";
const char* OH_AVMETA_KEY_WIDTH = "width";
const char* OH_AVMETA_KEY_HEIGHT = "height";
const char* OH_AVMETA_KEY_CHANNEL_COUNT = "channel_count";
const char* OH_AVMETA_KEY_SAMPLE_RATE = "sample_rate";
const char* OH_AVMETA_KEY_SAMPLE_DEPTH = "sample_depth";
const char* OH_AVMETA_KEY_LANGUAGE = "language";
const char* OH_AVMETA_KEY_TRACK_NAME = "track_name";
const char* OH_AVMETA_KEY_HDR_TYPE = "hdr_type";
const char* OH_AVMETA_KEY_ORIGINAL_WIDTH = "original_width";
const char* OH_AVMETA_KEY_ORIGINAL_HEIGHT = "original_height";
const char* OH_AVMETADATA_EXTRACTOR_REF_TRACK_IDS = "ref_track_ids";
const char* OH_AVMETADATA_EXTRACTOR_TRACK_REF_TYPE = "track_ref_type";
