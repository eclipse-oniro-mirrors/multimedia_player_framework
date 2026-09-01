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
#include "test_template.h"
#include <cmath>
#include <cstring>
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
constexpr uint32_t MAX_READ_LENGTH = 1024;

void AudioDataSourceFuzzer::Init()
{
    auto policy = static_cast<AudioCombinePolicy>(GetData<uint8_t>() % COMBINE_POLICY_COUNT);
    bool withVideo = static_cast<bool>(GetData<uint8_t>() % COMBINE_POLICY_COUNT);
    audioSource_ = std::make_shared<AudioDataSourceGeneric>(policy, withVideo);
}

void AudioDataSourceFuzzer::Release()
{
    audioSource_ = nullptr;
}

std::shared_ptr<CacheBuffer> AudioDataSourceFuzzer::CreateAudioBuffer(int64_t timestamp)
{
    auto buf = std::make_unique<uint8_t[]>(datasize);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), datasize, timestamp);
    return cacheBuf;
}

std::shared_ptr<AVBuffer> AudioDataSourceFuzzer::CreateAVBuffer()
{
    AVbuf.resize(datasize);
    auto avBuffer = AVBuffer::CreateAVBuffer(AVbuf.data(), datasize);
    return avBuffer;
}

bool AudioDataSourceFuzzer::FuzzReadAt()
{
    Init();
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % MAX_READ_LENGTH + 1;
    audioSource_->ReadAt(buffer, length);
    audioSource_->ReadAt(nullptr, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetSize()
{
    Init();
    int64_t size = 0;
    audioSource_->GetSize(size);
    audioSource_->cacheBuffer_ = CreateAudioBuffer(GetData<int64_t>());
    audioSource_->GetSize(size);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetVideoFirstFramePts()
{
    Init();
    int64_t pts = GetData<int64_t>();
    audioSource_->SetVideoFirstFramePts(pts);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzPauseResume()
{
    Init();
    audioSource_->Resume();
    audioSource_->Pause();
    audioSource_->Resume();
    audioSource_->Resume();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzStop()
{
    Init();
    audioSource_->Stop();
    audioSource_->ReadAudioBuffer();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzOnBufferAvailable()
{
    Init();
    auto type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % AUDIO_SOURCE_TYPE_COUNT);
    audioSource_->OnBufferAvailable(type);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetCapture()
{
    Init();
    auto type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % AUDIO_SOURCE_TYPE_COUNT);
    audioSource_->SetCapture(type, nullptr);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAudioBuffer()
{
    Init();
    audioSource_->firstVideoFramePts_.store(GetData<int64_t>());
    audioSource_->avSynced_ = static_cast<bool>(GetData<uint8_t>() % COMBINE_POLICY_COUNT);
    audioSource_->active_.store(static_cast<bool>(GetData<uint8_t>() % COMBINE_POLICY_COUNT));

    int32_t numSlots = GetData<uint8_t>() % MAX_SLOTS;
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % AUDIO_SOURCE_TYPE_COUNT);
        auto state = static_cast<CaptureSlotState>(GetData<uint8_t>() % SLOT_STATE_COUNT);
        auto buf = GetData<uint8_t>() % COMBINE_POLICY_COUNT ? CreateAudioBuffer(GetData<int64_t>()) : nullptr;
        audioSource_->captures_.push_back({type, nullptr, state, buf, GetData<int64_t>()});
    }
    audioSource_->ReadAudioBuffer();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzLostFrameNum()
{
    Init();
    audioSource_->firstVideoFramePts_.store(GetData<int64_t>());
    audioSource_->writedFrameTime_ = GetData<int64_t>();
    audioSource_->pauseDuration_.store(GetData<int64_t>());
    int64_t ts = GetData<int64_t>();
    audioSource_->LostFrameNum(ts);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzAlignOrCombine()
{
    Init();
    int32_t numSlots = GetData<uint8_t>() % MAX_SLOTS;
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % AUDIO_SOURCE_TYPE_COUNT);
        auto state = static_cast<CaptureSlotState>(GetData<uint8_t>() % SLOT_STATE_COUNT);
        auto buf = GetData<uint8_t>() % COMBINE_POLICY_COUNT ? CreateAudioBuffer(GetData<int64_t>()) : nullptr;
        audioSource_->captures_.push_back({type, nullptr, state, buf, GetData<int64_t>()});
    }
    audioSource_->AlignOrCombine();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzCombine()
{
    Init();
    int32_t numSlots = GetData<uint8_t>() % MAX_MIX_SRCS;
    audioSource_->captures_.clear();
    for (int32_t i = 0; i < numSlots; i++) {
        auto type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % AUDIO_SOURCE_TYPE_COUNT);
        auto state = static_cast<CaptureSlotState>(GetData<uint8_t>() % SLOT_STATE_COUNT);
        auto buf = CreateAudioBuffer(GetData<int64_t>());
        auto lastTs = GetData<int64_t>();
        audioSource_->captures_.push_back({type, nullptr, state, buf, lastTs});
    }
    audioSource_->Combine();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzMixAudio()
{
    Init();
    int32_t numSrcs = GetData<uint8_t>() % MAX_MIX_SRCS + 1;
    std::vector<const CacheBuffer *> srcs;
    std::vector<std::shared_ptr<CacheBuffer>> holders;
    for (int32_t i = 0; i < numSrcs; i++) {
        auto buf = CreateAudioBuffer(GetData<int64_t>());
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

bool FuzzAudioDataSourceCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    AudioDataSourceFuzzer fuzzer;
    fuzzer.FuzzReadAt();
    fuzzer.FuzzGetSize();
    fuzzer.FuzzSetVideoFirstFramePts();
    fuzzer.FuzzPauseResume();
    fuzzer.FuzzStop();
    fuzzer.FuzzOnBufferAvailable();
    fuzzer.FuzzSetCapture();
    fuzzer.FuzzReadAudioBuffer();
    fuzzer.FuzzLostFrameNum();
    fuzzer.FuzzAlignOrCombine();
    fuzzer.FuzzCombine();
    fuzzer.FuzzMixAudio();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    FuzzAudioDataSourceCase(data, size);
    return 0;
}
} // namespace Media
} // namespace OHOS
