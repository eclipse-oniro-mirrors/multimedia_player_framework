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

#ifndef OH_VEF_VIDEO_ENCODER_ENGINE_IMPL_H
#define OH_VEF_VIDEO_ENCODER_ENGINE_IMPL_H

#include "codec/audio/encoder/audio_encoder.h"
#include "codec/video_encoder_engine.h"
#include "ffrt.h"
#include "native_avsource.h"
#include "video_encoder.h"
#include "video_muxer.h"
#include "video_editor.h"
#include <list>
#include <native_avdemuxer.h>
#include <native_avsource.h>
namespace OHOS {
namespace Media {

enum class DecodeEngineState {
    INIT = 0,
    RUNNING,
    FINISH_SUCCESS,
    FINISH_FAILED,
    CANCEL
};

class VideoEncoderEngineImpl : public IVideoEncoderEngine {
public:
    VideoEncoderEngineImpl(uint64_t id, VideoEncodeCallback* cb);
    virtual ~VideoEncoderEngineImpl();

    uint64_t GetId() const override;
    VEFError StartEncode() override;
    VEFError StopEncode() override;
    VEFError SendEos() override;
    VEFError Flush() override;
    OHNativeWindow* GetVideoInputWindow() override;
    VEFError Init(const VideoEncodeParam& encodeParam) override;
    std::shared_ptr<PcmBufferQueue> GetAudioInputBufferQueue() const override;

private:
    VEFError InitVideoMuxer(const VideoMuxerParam& muxerParam);
    VEFError InitAudioStreamEncoder(OH_AVFormat* audioFormat);
    VEFError InitVideoStreamEncoder(OH_AVFormat* videoFormat);
    void UnInit();
    void OnVideoNewOutputDataCallBack(OH_AVMemory* data, OH_AVCodecBufferAttr* attr);
    void OnEncodeResult(CodecResult result);
    VEFError OnAudioEncodeOutput(OH_AVCodec *codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr);

private:
    uint64_t id_{ 0 };
    std::string logTag_;
    VideoEncodeCallback* cb_;
    std::shared_ptr<VideoEncoder> encoder_{ nullptr };
    std::shared_ptr<AudioEncoder> audioEncoder_{ nullptr };
    std::shared_ptr<VideoMuxer> muxer_{ nullptr };
    std::mutex streamFinishMutex_;

    // audio renderer
    std::list<PcmData> pcmDataList_;

    CodecState audioEncoderState_ { CodecState::INIT };
    CodecState videoEncoderState_ { CodecState::INIT };
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_ENCODER_ENGINE_IMPL_H