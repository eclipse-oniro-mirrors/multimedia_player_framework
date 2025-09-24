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
#ifndef MEDIA_AVCODEC_COMMOM_H
#define MEDIA_AVCODEC_COMMOM_H

#include <string>
#include <vector>
#include <map>
#include "av_common.h"
#include "buffer/avbuffer.h"
#include "meta/format.h"

namespace OHOS {
namespace MediaAVCodec {
using AVBuffer = OHOS::Media::AVBuffer;
using Format = OHOS::Media::Format;
enum AVCodecErrorType : int32_t {
    AVCODEC_ERROR_INTERNAL,
    AVCODEC_ERROR_DECRYTION_FAILED,
    AVCODEC_ERROR_FRAMEWORK_FAILED,
    AVCODEC_ERROR_EXTEND_START = 0X10000,
};

enum class API_VERSION : int32_t {
    API_VERSION_10 = 10,
    API_VERSION_11 = 11
};

enum AVCodecBufferFlag : uint32_t {
    AVCODEC_BUFFER_FLAG_NONE = 0,
    AVCODEC_BUFFER_FLAG_EOS = 1 << 0,
    AVCODEC_BUFFER_FLAG_SYNC_FRAME = 1 << 1,
    AVCODEC_BUFFER_FLAG_PARTIAL_FRAME = 1 << 2,
    AVCODEC_BUFFER_FLAG_CODEC_DATA = 1 << 3,
    AVCODEC_BUFFER_FLAG_DISCARD = 1 << 4,
    AVCODEC_BUFFER_FLAG_DISPOSABLE = 1 << 5,
    AVCODEC_BUFFER_FLAG_DISPOSABLE_EXT = 1 << 6,
    AVCODEC_BUFFER_FLAG_MUL_FRAME = 1 << 7,
};

struct AVCodecBufferInfo {
    int64_t presentationTimeUs = 0;
    int32_t size = 0;
    int32_t offset = 0;
};

class AVCodecCallback {
public:
    virtual void OnError(AVCodecErrorType errorType, int32_t errorCode) = 0;
    virtual void OnOutputFormatChanged(const Format &format) = 0;
};

class AVDemuxerCallback {
public:
    virtual ~AVDemuxerCallback() = default;
    virtual void OnDrmInfoChanged(const std::multimap<std::string, std::vector<uint8_t>> &drmInfo) = 0;
};

class MediaCodecCallback {
public:
    virtual ~MediaCodecCallback() = default;
    virtual void OnError(AVCodecErrorType errorType, int32_t errorCode) = 0;
    virtual void OnOutputFormatChanged(const Format &format) = 0;
    virtual void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) = 0;
    virtual void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) = 0;
    virtual void OnOutputBufferBinded(std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap)
    {
        (void)bufferMap;
    }
    virtual void OnOutputBufferUnbinded()
    {
    }
};

class MediaCodecParameterCallback {
public:
    virtual ~MediaCodecParameterCallback() = default;
    virtual void OnInputParameterAvailable(uint32_t index, std::shared_ptr<Format> parameter) = 0;
};

class MediaCodecParameterWithAttrCallback {
public:
    virtual ~MediaCodecParameterWithAttrCallback() = default;
    virtual void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format> attribute,
                                                   std::shared_ptr<Format> parameter) = 0;
};

class SurfaceBufferExtratDataKey {
public:
    static constexpr std::string_view ED_KEY_TIME_STAMP = "timeStamp";
    static constexpr std::string_view ED_KEY_END_OF_STREAM = "endOfStream";

private:
    SurfaceBufferExtratDataKey() = delete;
    ~SurfaceBufferExtratDataKey() = delete;
};

class AVSourceFormat {
public:
    static constexpr std::string_view SOURCE_TITLE         = "title";            // string, title
    static constexpr std::string_view SOURCE_ARTIST        = "artist";           // string, artist
    static constexpr std::string_view SOURCE_ALBUM         = "album";            // string, album
    static constexpr std::string_view SOURCE_ALBUM_ARTIST  = "album_artist";     // string, album artist
    static constexpr std::string_view SOURCE_DATE          = "date";             // string, media date,
                                                                                 // format: YYYY-MM-DD
    static constexpr std::string_view SOURCE_COMMENT       = "comment";          // string, comment
    static constexpr std::string_view SOURCE_GENRE         = "genre";            // string, genre
    static constexpr std::string_view SOURCE_COPYRIGHT     = "copyright";        // string, copyright
    static constexpr std::string_view SOURCE_LANGUAGE      = "language";         // string, language
    static constexpr std::string_view SOURCE_DESCRIPTION   = "description";      // string, description
    static constexpr std::string_view SOURCE_LYRICS        = "lyrics";           // string, cyrics

    static constexpr std::string_view SOURCE_FILE_TYPE     = "file_type";        // string, type
    static constexpr std::string_view SOURCE_HAS_VIDEO     = "has_video";        // bool, contain video tracks
    static constexpr std::string_view SOURCE_HAS_AUDIO     = "has_audio";        // bool, contain audio tracks
    static constexpr std::string_view SOURCE_HAS_TIMEDMETA = "has_timed_meta";   // bool, contain timed metadata tracks
    static constexpr std::string_view SOURCE_HAS_SUBTITLE  = "has_subtitle";     // bool, contain subtitle tracks
    static constexpr std::string_view SOURCE_AUTHOR        = "author";           // string, autbor
    static constexpr std::string_view SOURCE_COMPOSER      = "composer";         // string, composer
private:
    AVSourceFormat() = delete;
    ~AVSourceFormat() = delete;
};

enum VideoBitStreamFormat {
    UNKNOWN = 0,
    AVCC,
    HVCC,
    ANNEXB
};

struct CUVVConfigBox {
    uint16_t cuva_version_map;
    uint16_t terminal_provide_code;
    uint16_t terminal_provide_oriented_code;
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // MEDIA_AVCODEC_COMMOM_H
