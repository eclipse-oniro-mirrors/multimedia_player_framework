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
#ifndef LPP_VDEC_ADAPTER_H
#define LPP_VDEC_ADAPTER_H

#include <gmock/gmock.h>
#include <string>
#include <deque>

#include "refbase.h"
#include "pipeline/pipeline.h"
#include "meta/format.h"
#include "video_decoder_adapter.h"
#include "lpp_video_data_manager.h"

#include "i_lpp_video_streamer.h"
#include "i_lpp_sync_manager.h"
#include "lpp_vdec_adapter.h"
#include "avcodec_errors.h"

namespace OHOS {
namespace Media {
class LppVideoDecoderAdapter : public std::enable_shared_from_this<LppVideoDecoderAdapter> {
public:
    explicit LppVideoDecoderAdapter(const std::string &streamerId, bool isLpp)
    {
        (void)streamerId;
        (void)isLpp;
    }
    ~LppVideoDecoderAdapter() {};
    MOCK_METHOD(int32_t, Init, (const std::string &mime, bool &switchToCommon));
    MOCK_METHOD(int32_t, Configure, (const Format &param));
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface));
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, StartDecode, ());
    MOCK_METHOD(int32_t, StartRender, ());
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Resume, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, SetParameter, (const Format &param));
    MOCK_METHOD(int32_t, SetCallback, (const std::shared_ptr<MediaAVCodec::MediaCodecCallback> &callback));
    MOCK_METHOD(int32_t, GetChannelId, (int32_t &channelId));
    MOCK_METHOD(int32_t, RenderFirstFrame, ());
    MOCK_METHOD(int32_t, Release, ());
    MOCK_METHOD(void, SetChannelIdDone, ());
    MOCK_METHOD(sptr<Media::AVBufferQueueProducer>, GetInputBufferQueue, ());
    MOCK_METHOD(void, OnQueueBufferAvailable, ());
    MOCK_METHOD(void, OnInputBufferAvailable, (uint32_t index, std::shared_ptr<AVBuffer> buffer));
    MOCK_METHOD(void, OnOutputBufferAvailable, (uint32_t index, std::shared_ptr<AVBuffer> buffer));
    MOCK_METHOD(void, OnOutputBufferBinded, ((std::map<uint32_t, sptr<SurfaceBuffer>>) &bufferMap));
    MOCK_METHOD(void, OnOutputBufferUnbinded, ());
    MOCK_METHOD(void, OnError, (MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode));
    MOCK_METHOD(void, OnOutputFormatChanged, (const MediaAVCodec::Format &format));
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver));
    MOCK_METHOD(void, SetSyncManager, (std::shared_ptr<ILppSyncManager> syncMgr));
    MOCK_METHOD(void, SetPlaybackSpeed, (float speed));
    MOCK_METHOD(int32_t, SetTargetPts, (int64_t targetPts));
};
}  // namespace Media
}  // namespace OHOS
#endif