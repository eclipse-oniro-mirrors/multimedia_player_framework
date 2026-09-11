/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "audiodatasource_fuzzer.h"
#include "aw_common.h"
#include "directory_ex.h"
#include "i_standard_screen_capture_service.h"
#include "media_errors.h"
#include "media_log.h"
#include "screen_capture.h"
#include "screen_capture_server.h"
#include "string_ex.h"
#include <cmath>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <unistd.h>

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {

constexpr int32_t AUDIO_SOURCE_TYPE_COUNT = 4;
constexpr int32_t COMBINE_POLICY_COUNT = 2;
constexpr uint32_t MAX_READ_LENGTH = 1024;

void AudioDataSourceFuzzer::Init(FuzzedDataProvider &fdp)
{
    auto policy = static_cast<AudioCombinePolicy>(fdp.ConsumeIntegralInRange<uint8_t>(0, COMBINE_POLICY_COUNT - 1));
    bool withVideo = fdp.ConsumeBool();
    audioSource_ = std::make_shared<AudioDataSourceGeneric>(policy, withVideo);
}

void AudioDataSourceFuzzer::Release()
{
    audioSource_ = nullptr;
}

std::shared_ptr<CacheBuffer> AudioDataSourceFuzzer::CreateAudioBuffer(int64_t timestamp)
{
    auto buf = std::make_unique<uint8_t[]>(datasize);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), datasize, timestamp, 0);
    return cacheBuf;
}

std::shared_ptr<AVBuffer> AudioDataSourceFuzzer::CreateAVBuffer()
{
    AVbuf.resize(datasize);
    auto avBuffer = AVBuffer::CreateAVBuffer(AVbuf.data(), datasize);
    return avBuffer;
}

bool AudioDataSourceFuzzer::FuzzReadAt(FuzzedDataProvider &fdp)
{
    Init(fdp);
    auto buffer = CreateAVBuffer();
    uint32_t length = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_READ_LENGTH);
    audioSource_->ReadAt(buffer, length);
    audioSource_->ReadAt(nullptr, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetSize(FuzzedDataProvider &fdp)
{
    Init(fdp);
    int64_t size = 0;
    audioSource_->GetSize(size);
    audioSource_->cacheBuffer_ = CreateAudioBuffer(fdp.ConsumeIntegral<int64_t>());
    audioSource_->GetSize(size);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetVideoFirstFramePts(FuzzedDataProvider &fdp)
{
    Init(fdp);
    int64_t pts = fdp.ConsumeIntegral<int64_t>();
    audioSource_->SetVideoFirstFramePts(pts);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzPauseResume(FuzzedDataProvider &fdp)
{
    Init(fdp);
    audioSource_->Resume();
    audioSource_->Pause();
    audioSource_->Resume();
    audioSource_->Resume();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzStop(FuzzedDataProvider &fdp)
{
    Init(fdp);
    audioSource_->Stop();
    audioSource_->ReadAudioBuffer();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzOnBufferAvailable(FuzzedDataProvider &fdp)
{
    Init(fdp);
    auto type = static_cast<AudioCaptureSourceType>(
        fdp.ConsumeIntegralInRange<uint8_t>(0, AUDIO_SOURCE_TYPE_COUNT - 1));
    audioSource_->OnBufferAvailable(type);
    Release();
    return true;
}

bool FuzzAudioDataSourceCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return true;
    }
    FuzzedDataProvider fdp(data, size);
    AudioDataSourceFuzzer fuzzer;
    fuzzer.FuzzReadAt(fdp);
    fuzzer.FuzzGetSize(fdp);
    fuzzer.FuzzSetVideoFirstFramePts(fdp);
    fuzzer.FuzzPauseResume(fdp);
    fuzzer.FuzzStop(fdp);
    fuzzer.FuzzOnBufferAvailable(fdp);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    FuzzAudioDataSourceCase(data, size);
    return 0;
}
} // namespace Media
} // namespace OHOS
