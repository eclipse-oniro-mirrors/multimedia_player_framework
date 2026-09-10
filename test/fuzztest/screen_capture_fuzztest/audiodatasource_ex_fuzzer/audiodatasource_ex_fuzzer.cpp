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

#include "audiodatasource_ex_fuzzer.h"
#include "aw_common.h"
#include "directory_ex.h"
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
constexpr int32_t SLOT_STATE_COUNT = 3;
constexpr int32_t COMBINE_POLICY_COUNT = 2;
constexpr int32_t MAX_SLOTS = 3;
constexpr int32_t MAX_MIX_SRCS = 4;

void AudioDataSourceExFuzzer::Init(FuzzedDataProvider &fdp)
{
    auto policy = static_cast<AudioCombinePolicy>(fdp.ConsumeIntegralInRange<uint8_t>(0, COMBINE_POLICY_COUNT - 1));
    bool withVideo = fdp.ConsumeBool();
    audioSource_ = std::make_shared<AudioDataSourceGeneric>(policy, withVideo);
}

void AudioDataSourceExFuzzer::Release()
{
    audioSource_ = nullptr;
}

std::shared_ptr<CacheBuffer> AudioDataSourceExFuzzer::CreateAudioBuffer(int64_t timestamp)
{
    return CreateAudioBuffer(timestamp, datasize);
}

std::shared_ptr<CacheBuffer> AudioDataSourceExFuzzer::CreateAudioBuffer(int64_t timestamp, int32_t size)
{
    auto buf = std::make_unique<uint8_t[]>(size);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), size, timestamp);
    return cacheBuf;
}

bool AudioDataSourceExFuzzer::FuzzSetCapture(FuzzedDataProvider &fdp)
{
    Init(fdp);
    auto type = static_cast<AudioCaptureSourceType>(
        fdp.ConsumeIntegralInRange<uint8_t>(0, AUDIO_SOURCE_TYPE_COUNT - 1));
    audioSource_->SetCapture(type, nullptr);
    Release();
    return true;
}

bool AudioDataSourceExFuzzer::FuzzReadAudioBuffer(FuzzedDataProvider &fdp)
{
    Init(fdp);
    audioSource_->firstVideoFramePts_.store(fdp.ConsumeIntegral<int64_t>());
    audioSource_->avSynced_ = fdp.ConsumeBool();
    audioSource_->active_.store(fdp.ConsumeBool());

    int32_t numSlots = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_SLOTS - 1);
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(
            fdp.ConsumeIntegralInRange<uint8_t>(0, AUDIO_SOURCE_TYPE_COUNT - 1));
        auto state = static_cast<CaptureSlotState>(fdp.ConsumeIntegralInRange<uint8_t>(0, SLOT_STATE_COUNT - 1));
        auto buf = fdp.ConsumeBool() ? CreateAudioBuffer(fdp.ConsumeIntegral<int64_t>()) : nullptr;
        audioSource_->captures_.push_back({type, nullptr, state, buf, fdp.ConsumeIntegral<int64_t>()});
    }
    audioSource_->ReadAudioBuffer();
    Release();
    return true;
}

bool AudioDataSourceExFuzzer::FuzzLostFrameNum(FuzzedDataProvider &fdp)
{
    Init(fdp);
    audioSource_->firstVideoFramePts_.store(fdp.ConsumeIntegral<int64_t>());
    audioSource_->writedFrameTime_ = fdp.ConsumeIntegral<int64_t>();
    audioSource_->pauseDuration_.store(fdp.ConsumeIntegral<int64_t>());
    int64_t ts = fdp.ConsumeIntegral<int64_t>();
    audioSource_->LostFrameNum(ts);
    Release();
    return true;
}

bool AudioDataSourceExFuzzer::FuzzAlignOrCombine(FuzzedDataProvider &fdp)
{
    Init(fdp);
    int32_t numSlots = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_SLOTS - 1);
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(
            fdp.ConsumeIntegralInRange<uint8_t>(0, AUDIO_SOURCE_TYPE_COUNT - 1));
        auto state = static_cast<CaptureSlotState>(fdp.ConsumeIntegralInRange<uint8_t>(0, SLOT_STATE_COUNT - 1));
        auto buf = fdp.ConsumeBool() ? CreateAudioBuffer(fdp.ConsumeIntegral<int64_t>()) : nullptr;
        audioSource_->captures_.push_back({type, nullptr, state, buf, fdp.ConsumeIntegral<int64_t>()});
    }
    audioSource_->AlignOrCombine();
    Release();
    return true;
}

bool AudioDataSourceExFuzzer::FuzzCombine(FuzzedDataProvider &fdp)
{
    Init(fdp);
    int32_t numSlots = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_MIX_SRCS - 1);
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(
            fdp.ConsumeIntegralInRange<uint8_t>(0, AUDIO_SOURCE_TYPE_COUNT - 1));
        auto state = static_cast<CaptureSlotState>(fdp.ConsumeIntegralInRange<uint8_t>(0, SLOT_STATE_COUNT - 1));
        auto buf = CreateAudioBuffer(fdp.ConsumeIntegral<int64_t>());
        auto lastTs = fdp.ConsumeIntegral<int64_t>();
        audioSource_->captures_.push_back({type, nullptr, state, buf, lastTs});
    }
    audioSource_->Combine();
    Release();
    return true;
}

bool AudioDataSourceExFuzzer::FuzzMixAudio(FuzzedDataProvider &fdp)
{
    Init(fdp);
    int32_t numSrcs = fdp.ConsumeIntegralInRange<int32_t>(1, MAX_MIX_SRCS);
    std::vector<const CacheBuffer *> srcs;
    std::vector<std::shared_ptr<CacheBuffer>> holders;
    for (int32_t i = 0; i < numSrcs; i++) {
        auto ts = fdp.ConsumeIntegral<int64_t>();
        int32_t size = (i == 0) ? datasize : fdp.ConsumeIntegralInRange<int32_t>(0, datasize);
        auto buf = CreateAudioBuffer(ts, size);
        holders.push_back(buf);
        srcs.push_back(buf.get());
    }
    auto out = std::make_unique<uint8_t[]>(datasize);
    audioSource_->MixAudio(srcs, out.get());
    srcs.clear();
    for (size_t i = 0; i < holders.size(); i++) {
        srcs.push_back(i % COMBINE_POLICY_COUNT ? holders[i].get() : nullptr);
    }
    audioSource_->MixAudio(srcs, out.get());
    Release();
    return true;
}

bool FuzzAudioDataSourceExCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return true;
    }
    FuzzedDataProvider fdp(data, size);
    AudioDataSourceExFuzzer fuzzer;
    fuzzer.FuzzSetCapture(fdp);
    fuzzer.FuzzReadAudioBuffer(fdp);
    fuzzer.FuzzLostFrameNum(fdp);
    fuzzer.FuzzAlignOrCombine(fdp);
    fuzzer.FuzzCombine(fdp);
    fuzzer.FuzzMixAudio(fdp);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    FuzzAudioDataSourceExCase(data, size);
    return 0;
}
} // namespace Media
} // namespace OHOS
