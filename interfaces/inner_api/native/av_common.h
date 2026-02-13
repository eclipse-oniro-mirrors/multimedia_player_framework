/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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
#ifndef AV_COMMOM_H
#define AV_COMMOM_H

#include <vector>
#include <string>
#include "meta/format.h"
#include "media_core.h"

namespace OHOS {
namespace Media {
/**
 * @brief
 *
 * @since 3.1
 * @version 3.1
 */
enum VideoPixelFormat {
    /**
     * yuv 420 planar.
     */
    YUVI420 = 1,
    /**
     *  NV12. yuv 420 semiplanar.
     */
    NV12 = 2,
    /**
     *  NV21. yvu 420 semiplanar.
     */
    NV21 = 3,
    /**
     * format from surface.
     */
    SURFACE_FORMAT = 4,
    /**
     * RGBA.
     */
    RGBA = 5,
};

/**
 * @brief Enumerates the video rotation.
 *
 * @since 3.2
 * @version 3.2
 */
enum VideoRotation : uint32_t {
    /**
    * Video without rotation
    */
    VIDEO_ROTATION_0 = 0,
    /**
    * Video rotated 90 degrees
    */
    VIDEO_ROTATION_90 = 90,
    /**
    * Video rotated 180 degrees
    */
    VIDEO_ROTATION_180 = 180,
    /**
    * Video rotated 270 degrees
    */
    VIDEO_ROTATION_270 = 270,
};

/**
 * @brief Enumerates output format types.
 *
 * @since 3.1
 * @version 3.1
 */
enum OutputFormatType : int32_t {
    /** Default format */
    FORMAT_DEFAULT = 0,
    /** MPEG4 format */
    FORMAT_MPEG_4 = 2,
    /** M4A format */
    FORMAT_M4A = 6,
    /** AMR format */
    FORMAT_AMR = 8,
    /** mp3 format */
    FORMAT_MP3 = 9,
    /** WAV format */
    FORMAT_WAV = 10,
    /** AAC format */
    FORMAT_AAC = 11,
    /** BUTT */
    FORMAT_BUTT,
};

/**
 * @brief Enumerates video codec formats.
 *
 * @since 3.1
 * @version 3.1
 */
enum VideoCodecFormat : int32_t {
    /** Default format */
    VIDEO_DEFAULT = 0,
    /** H.264 */
    H264 = 2,
    /** MPEG4 */
    MPEG4 = 6,
    /** H.265 */
    H265 = 8,
    VIDEO_CODEC_FORMAT_BUTT,
};

/**
 * @brief Enumerates audio aac formats.
 *
 * @since 22
 * @version 6.0
 */
enum class AacProfile : int32_t {
    AAC_LC = 0,
    
    AAC_HE = 1,
    
    AAC_HE_V2 = 2,

    AUDIO_CODEC_FORMAT_BUTT,
};

/**
 * @brief Enumerates audio codec formats.
 *
 * @since 3.1
 * @version 3.1
 */
enum AudioCodecFormat : int32_t {
    /** Default format */
    AUDIO_DEFAULT = 0,
    /** Advanced Audio Coding Low Complexity (AAC-LC) */
    AAC_LC = 3,
    /** mp3 format */
    AUDIO_MPEG = 4,
    /** G711-mulaw format */
    AUDIO_G711MU = 5,
    /** AUDIO_AMR_NB format */
    AUDIO_AMR_NB = 9,
    /** AUDIO_AMR_WB format */
    AUDIO_AMR_WB = 10,
    /** Invalid value */
    AUDIO_CODEC_FORMAT_BUTT,
};

class AVMimeType {
public:
    static constexpr std::string_view APPLICATION_M3U8 = "application/m3u8";
};
} // namespace Media
} // namespace OHOS
#endif // AV_COMMOM_H