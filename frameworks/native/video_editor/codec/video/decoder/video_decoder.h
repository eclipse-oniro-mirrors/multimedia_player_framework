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

#ifndef OH_VEF_VIDEO_DECODER_H
#define OH_VEF_VIDEO_DECODER_H

#include <string>
#include "ffrt.h"
#include <native_avdemuxer.h>
#include <native_avsource.h>
#include <native_avformat.h>
#include "codec/video_decoder_engine.h"
#include "codec/video/decoder/video_demuxer.h"
#include "codec/common/codec_common.h"
#include "video_editor.h"

namespace OHOS {
namespace Media {

class VideoDecoder {
public:
    VideoDecoder(uint64_t id, const CodecOnInData& packetReadFunc,
        const CodecOnDecodeFrame& onDecodeFrameCallback, const CodecOnDecodeResult& onDecodeResultCallback);
    ~VideoDecoder();

public:
    VEFError Init(OH_AVFormat* videoFormat);
    VEFError SetNativeWindow(OHNativeWindow* surfaceWindow);
    VEFError Start();
    VEFError Stop();

private:
    VEFError CreateDecoder();
    VEFError ConfigureDecoder(OH_AVFormat* videoFormat);
    void CodecOnStreamChangedInner(OH_AVFormat* format);
    void CodecOnNeedInputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data);
    void CodecOnNewOutputData(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr);

private:
    std::string logTag_ = "";
    OH_AVCodec* decoder_{ nullptr };
    std::string codecMime_ = "";
    CodecOnInData packetReadFunc_{ nullptr };
    CodecOnDecodeFrame onDecodeFrameCallback_{ nullptr };
    CodecOnDecodeResult onDecodeResultCallback_{ nullptr };
    CodecState state_{ CodecState::INIT };
    ffrt::task_handle taskHandle_{ nullptr };
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_DECODER_H
