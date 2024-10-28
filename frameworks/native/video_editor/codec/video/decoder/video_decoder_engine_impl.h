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

#ifndef OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H
#define OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H

#include <cstdint>
#include <string>
#include <list>
#include "native_avsource.h"
#include <native_avdemuxer.h>
#include <native_avcodec_videodecoder.h>
#include "video_decoder.h"
#include "video_demuxer.h"
#include "codec/audio/decoder/audio_decoder.h"
#include "codec/video_decoder_engine.h"

namespace OHOS {
namespace Media {

class VideoDecoderEngineImpl : public IVideoDecoderEngine {
public:
    VideoDecoderEngineImpl(uint64_t id, int fd, VideoDecodeCallback* cb);
    virtual ~VideoDecoderEngineImpl();

public:
    uint64_t GetId() const override;
    VEFError SetVideoOutputWindow(OHNativeWindow* surfaceWindow) override;
    void SetAudioOutputBufferQueue(std::shared_ptr<PcmBufferQueue>& queue) override;
    VEFError StartDecode() override;
    VEFError StopDecode() override;
    OH_AVFormat* GetVideoFormat() override;
    OH_AVFormat* GetAudioFormat() override;
    int32_t GetRotation() const override;
    int64_t GetVideoDuration() const override;

    VEFError Init() override;

private:
    VEFError InitDeMuxer();
    VEFError InitDecoder();
    VEFError InitAudioDecoder();
    VEFError ReadVideoPacket(OH_AVMemory* packet, OH_AVCodecBufferAttr* attr);
    VEFError ReadAudioPacket(OH_AVMemory* packet, OH_AVCodecBufferAttr* attr);
    void OnAudioDecodeFrame(uint64_t pts);
    void OnAudioDecodeResult(CodecResult result);
    void OnVideoDecoderFrame(uint64_t pts);
    void OnVideoDecodeResult(CodecResult result);
    void NotifyDecodeResult();

private:
    uint64_t id_ = 0;
    int fd_ = -1;
    std::string logTag_ = "";
    VideoDecodeCallback* cb_ { nullptr };
    std::shared_ptr<VideoDeMuxer> deMuxer_{ nullptr };
    std::shared_ptr<VideoDecoder> videoDecoder_ { nullptr };
    std::shared_ptr<AudioDecoder> audioDecoder_ { nullptr };
    CodecState audioDecoderState_{ CodecState::INIT };
    CodecState videoDecoderState_{ CodecState::INIT };
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H