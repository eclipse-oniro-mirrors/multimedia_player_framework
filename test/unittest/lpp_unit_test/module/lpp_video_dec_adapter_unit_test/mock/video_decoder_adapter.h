/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_VDEC_ADAPTER_H
#define MOCK_VDEC_ADAPTER_H

#include <gmock/gmock.h>
#include "avcodec_errors.h"
#include "avcodec_common.h"

namespace OHOS {
namespace MediaAVCodec {
class AVCodecVideoDecoder : public std::enable_shared_from_this<AVCodecVideoDecoder> {
public:
    AVCodecVideoDecoder () {};
    ~AVCodecVideoDecoder() {};
    MOCK_METHOD(int32_t, Configure, (const Format &format));
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, Start, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, Release, ());
    MOCK_METHOD(int32_t, SetOutputSurface, (sptr<Surface> surface));
    MOCK_METHOD(int32_t, QueueInputBuffer, (uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag));
    MOCK_METHOD(int32_t, QueueInputBuffer, (uint32_t index));
    MOCK_METHOD(int32_t, GetOutputFormat, (Format &format));
    MOCK_METHOD(int32_t, ReleaseOutputBuffer, (uint32_t index, bool render));
    MOCK_METHOD(int32_t, RenderOutputBufferAtTime, (uint32_t index, int64_t renderTimestampNs));
    MOCK_METHOD(int32_t, SetParameter, (const Format &format));
    MOCK_METHOD(int32_t, SetCallback, (const std::shared_ptr<AVCodecCallback> &callback));
    int32_t SetCallback(const std::shared_ptr<MediaCodecCallback> &callback)
    {
        (void)callback;
        return MediaAVCodec::AVCS_ERR_OK;
    }
    MOCK_METHOD(int32_t, GetChannelId, (int32_t &channelId));
    int32_t SetLowPowerPlayerMode(bool isLpp)
    {
        (void)isLpp;
        return MediaAVCodec::AVCS_ERR_OK;
    }
    MOCK_METHOD(int32_t, NotifyMemoryExchange, (const bool exchangeFlag));
    MOCK_METHOD(int32_t, QueryInputBuffer, (uint32_t &index, int64_t timeoutUs));
    MOCK_METHOD(int32_t, QueryOutputBuffer, (uint32_t &index, int64_t timeoutUs));
    MOCK_METHOD(std::shared_ptr<AVBuffer>, GetInputBuffer, (uint32_t index));
    MOCK_METHOD(std::shared_ptr<AVBuffer>, GetOutputBuffer, (uint32_t index));
};

class VideoDecoderFactory {
public:
    static std::shared_ptr<AVCodecVideoDecoder> CreateByMime(const std::string &mime)
    {
        (void)mime;
        static std::shared_ptr<AVCodecVideoDecoder> instance = std::make_shared<AVCodecVideoDecoder>();
        return instance;
    }
private:
    VideoDecoderFactory() = default;
    ~VideoDecoderFactory() = default;
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // MOCK_VDEC_ADAPTER_H
