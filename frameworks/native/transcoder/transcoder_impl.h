/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef TRANSCODER_IMPL_H
#define TRANSCODER_IMPL_H

#include "transcoder.h"
#include "nocopyable.h"
#include "i_transcoder_service.h"
#include "hitrace/tracechain.h"

namespace OHOS {
namespace Media {
class TransCoderImpl : public TransCoder, public NoCopyable {
public:
    TransCoderImpl();
    ~TransCoderImpl();

    int32_t SetVideoEncoder(VideoCodecFormat encoder) override;
    int32_t SetVideoEncodingBitRate(int32_t rate) override;
    int32_t SetVideoSize(int32_t width, int32_t height) override;
    int32_t SetColorSpace(TranscoderColorSpace colorSpaceFormat) override;
    int32_t SetEnableBFrame(bool enableBFrame) override;
    int32_t SetAudioEncoder(AudioCodecFormat encoder) override;
    int32_t SetAudioEncodingBitRate(int32_t bitRate) override;
    int32_t SetOutputFormat(OutputFormatType format) override;
    int32_t SetInputFile(int32_t fd, int64_t offset, int64_t size) override;
    int32_t SetOutputFile(int32_t fd) override;
    int32_t SetTransCoderCallback(const std::shared_ptr<TransCoderCallback> &callback) override;
    int32_t Prepare() override;
    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Cancel() override;
    int32_t Release() override;
    int32_t Init();

private:
    std::shared_ptr<ITransCoderService> transCoderService_ = nullptr;
    HiviewDFX::HiTraceId traceId_;
};
} // namespace Media
} // namespace OHOS
#endif // TRANSCODER_IMPL_H
