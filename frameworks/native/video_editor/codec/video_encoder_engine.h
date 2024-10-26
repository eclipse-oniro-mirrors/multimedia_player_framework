/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_VIDEO_ENCODER_ENGINE_H
#define OH_VEF_VIDEO_ENCODER_ENGINE_H

#include "codec/common/codec_common.h"
#include <memory>
#include "video_editor.h"
#include "native_avcodec_base.h"
#include "codec/audio/pcm_buffer_queue.h"

namespace OHOS {
namespace Media {

class VideoEncodeCallback {
public:
    virtual void OnEncodeFrame(uint64_t pts) = 0;
    virtual void OnEncodeResult(CodecResult result) = 0;
};

struct VideoMuxerParam {
    int targetFileFd { -1 };
    OH_AVOutputFormat avOutputFormat = AV_OUTPUT_FORMAT_MPEG_4;
    int32_t rotation = 0;
};

struct VideoEncodeParam {
    VideoMuxerParam muxerParam;
    OH_AVFormat* videoTrunkFormat = nullptr;
    OH_AVFormat* audioTrunkFormat = nullptr;
};

class IVideoEncoderEngine {
public:
    static std::shared_ptr<IVideoEncoderEngine> Create(const VideoEncodeParam& encodeParam, VideoEncodeCallback* cb);

    virtual VEFError Init(const VideoEncodeParam& encodeParam) = 0;
    virtual uint64_t GetId() const = 0;
    virtual VEFError StartEncode() = 0;
    virtual VEFError StopEncode() = 0;
    virtual VEFError SendEos() = 0;
    virtual VEFError Flush() = 0;
    virtual OHNativeWindow* GetVideoInputWindow() = 0;
    virtual std::shared_ptr<PcmBufferQueue> GetAudioInputBufferQueue() const = 0;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_ENCODER_ENGINE_H