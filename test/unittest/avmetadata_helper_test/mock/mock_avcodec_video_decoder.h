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

#ifndef MOCK_MEDIA_AVCODEC_VIDEO_DECODER_H
#define MOCK_MEDIA_AVCODEC_VIDEO_DECODER_H

#include "gmock/gmock.h"
#include "avcodec_video_decoder.h"

namespace OHOS {
namespace MediaAVCodec {
class MockAVCodecVideoDecoder : public AVCodecVideoDecoder {
public:
    MockAVCodecVideoDecoder() = default;
    ~MockAVCodecVideoDecoder()  override = default;
    MOCK_METHOD(int32_t, Configure, (const Format &format), ());

    MOCK_METHOD(int32_t, Prepare, (), ());

    MOCK_METHOD(int32_t, Start, (), ());

    MOCK_METHOD(int32_t, Stop, (), ());

    MOCK_METHOD(int32_t, Flush, (), ());

    MOCK_METHOD(int32_t, Reset, (), ());

    MOCK_METHOD(int32_t, Release, (), ());

    MOCK_METHOD(int32_t, SetOutputSurface, (sptr<Surface> surfac), ());

    MOCK_METHOD(int32_t, QueueInputBuffer, (uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag), ());

    MOCK_METHOD(int32_t, QueueInputBuffer, (uint32_t index), ());

    MOCK_METHOD(int32_t, GetOutputFormat, (Format &format), ());

    MOCK_METHOD(int32_t, ReleaseOutputBuffer, (uint32_t index, bool render), ());

    MOCK_METHOD(int32_t, RenderOutputBufferAtTime, (uint32_t index, int64_t renderTimestampNs), ());

    MOCK_METHOD(int32_t, SetParameter, (const Format &format), ());

    MOCK_METHOD(int32_t, SetCallback, (const std::shared_ptr<AVCodecCallback> &callback), ());

    MOCK_METHOD(int32_t, SetCallback, (const std::shared_ptr<MediaCodecCallback> &callback), ());

    MOCK_METHOD(int32_t, SetDecryptConfig, (const sptr<DrmStandard::IMediaKeySessionService> &keySession,
        const bool svpFlag), ());
    MOCK_METHOD(int32_t, SetLowPowerPlayerMode, (const bool isLpp), (override));
    MOCK_METHOD(int32_t, GetChannelId, (int32_t &channelId), (override));
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // MEDIA_AVCODEC_VIDEO_DECODER_H