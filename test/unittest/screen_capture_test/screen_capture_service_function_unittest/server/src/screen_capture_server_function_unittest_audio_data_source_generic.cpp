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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "audio_capturer_wrapper.h"
#include "audio_data_source_generic.h"
#include "buffer/avbuffer.h"
#include "cache_buffer.h"
#include "media_data_source.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

class AudioDataSourceGenericTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}

    static std::shared_ptr<CacheBuffer> MakeBuf(int16_t val, int32_t count, int64_t ts,
        AudioCaptureSourceType type = AudioCaptureSourceType::ALL_PLAYBACK)
    {
        auto data = std::make_unique<uint8_t[]>(count * sizeof(int16_t));
        auto *p = reinterpret_cast<int16_t *>(data.get());
        for (int32_t i = 0; i < count; i++) {
            p[i] = val;
        }
        return std::make_shared<CacheBuffer>(std::move(data), count * static_cast<int32_t>(sizeof(int16_t)), ts, type);
    }

    static std::shared_ptr<AudioCapturerWrapper> MakeMockWrapper(AudioCaptureSourceType type)
    {
        AudioCaptureInfo info{};
        info.audioSource = type;
        ScreenCaptureContentFilter filter{};
        auto wrapper = std::make_shared<AudioCapturerWrapper>(info, nullptr, "test", filter);
        wrapper->captureState_.store(AudioCapturerWrapperState::CAPTURER_RECORDING);
        return wrapper;
    }

    static void PushBuf(const std::shared_ptr<AudioCapturerWrapper> &wrapper, int16_t val, int32_t count, int64_t ts)
    {
        wrapper->availBuffers_.push_back(MakeBuf(val, count, ts));
    }

    static std::shared_ptr<AVBuffer> MakeAVBuffer(uint32_t length)
    {
        auto buffer = std::make_shared<AVBuffer>();
        auto data = std::make_unique<uint8_t[]>(length);
        buffer->memory_ = AVMemory::CreateAVMemory(data.get(), length, 0);
        // Prevent data from being freed before AVMemory uses it
        auto *raw = data.release();
        (void)raw;
        return buffer;
    }
};

class MockListener : public IAudioDataSourceListener {
public:
    void OnAudioDataReady() override
    {
        count_++;
    }
    int32_t count_{0};
};

HWTEST_F(AudioDataSourceGenericTest, GetPolicy_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    EXPECT_EQ(src->GetPolicy(), AudioCombinePolicy::MIX_ALL);
}

HWTEST_F(AudioDataSourceGenericTest, GetPolicy_002, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::PASSTHROUGH, false);
    EXPECT_EQ(src->GetPolicy(), AudioCombinePolicy::PASSTHROUGH);
}

HWTEST_F(AudioDataSourceGenericTest, Stop_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    EXPECT_TRUE(src->active_.load());
    src->Stop();
    EXPECT_FALSE(src->active_.load());
}

HWTEST_F(AudioDataSourceGenericTest, ResumeWithoutPause_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->Resume();
    EXPECT_EQ(src->pauseDuration_.load(), 0);
    EXPECT_EQ(src->pauseStartTime_.load(), 0);
}

HWTEST_F(AudioDataSourceGenericTest, PauseThenResume_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->Pause();
    EXPECT_NE(src->pauseStartTime_.load(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    src->Resume();
    EXPECT_GT(src->pauseDuration_.load(), 0);
    EXPECT_EQ(src->pauseStartTime_.load(), 0);
}

HWTEST_F(AudioDataSourceGenericTest, DoubleResume_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->Pause();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    src->Resume();
    int64_t firstDuration = src->pauseDuration_.load();
    src->Resume();
    EXPECT_EQ(src->pauseDuration_.load(), firstDuration);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_Stopped_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->Stop();
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_NoCaptures_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_VideoPtsNotSet_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    EXPECT_EQ(src->firstVideoFramePts_.load(), -1);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_VideoPtsSet_NoCaptures_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->SetVideoFirstFramePts(1000);
    EXPECT_NE(src->firstVideoFramePts_.load(), -1);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// === Coverage: LogStats dedup ===

HWTEST_F(AudioDataSourceGenericTest, LogStats_UpdateDedup_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->logStats_.Update(AudioOutputTag::SINGLE, AudioCaptureSourceType::ALL_PLAYBACK);
    src->logStats_.Update(AudioOutputTag::SINGLE, AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(src->logStats_.size, 2u);
    src->logStats_.Update(AudioOutputTag::MIXED, AudioCaptureSourceType::SOURCE_DEFAULT);
    EXPECT_EQ(src->logStats_.type, AudioOutputTag::MIXED);
}

// === Coverage: OnBufferAvailable with cacheBuffer_ ===

HWTEST_F(AudioDataSourceGenericTest, OnBufferAvailable_CacheBufferExists_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto listener = std::make_shared<MockListener>();
    src->SetListener(listener);
    src->cacheBuffer_ = MakeBuf(100, 4, 0);
    src->OnBufferAvailable(AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(listener->count_, 1);
}

HWTEST_F(AudioDataSourceGenericTest, OnBufferAvailable_ReadAudioBufferOK_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto listener = std::make_shared<MockListener>();
    src->SetListener(listener);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(wrapper, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    src->OnBufferAvailable(AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(listener->count_, 1);
    EXPECT_NE(src->cacheBuffer_, nullptr);
}

// === Coverage: SetCapture null ===

HWTEST_F(AudioDataSourceGenericTest, SetCapture_NullCapture_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, nullptr);
    EXPECT_EQ(src->captures_[0].capture, nullptr);
}

// === Coverage: ReadAudioBuffer avSynced_ with cacheBuffer_ ===

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_AVSynced_CacheBufferSet_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetVideoFirstFramePts(10000);
    src->avSynced_ = true;
    src->cacheBuffer_ = MakeBuf(100, 4, 10000);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
}

// === Coverage: acquired < activeCount (wait-for-both) ===

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_WaitForBoth_StableMic_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    src->captures_[0].state = CaptureSlotState::STABLE;
    src->captures_[1].state = CaptureSlotState::STABLE;
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// === Coverage: VideoAudioSyncIfNeed no audio ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_NoAudioFound_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->SetVideoFirstFramePts(1000);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// === Coverage: VideoAudioSyncIfNeed MIX_ALL→AlignOrCombine ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_MIX_ALLPASSTHROUGH_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::PASSTHROUGH, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetVideoFirstFramePts(10000);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_TRUE(src->avSynced_);
}

// === Coverage: AlignOrCombine no currentBuf ===

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_NoCurrentBuf_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, nullptr, 0});
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// === Coverage: AlignOrCombine PASSTHROUGH multiple ===

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_PASSTHROUGHMultiple_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::PASSTHROUGH, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    auto stopped = MakeMockWrapper(AudioCaptureSourceType::APP_PLAYBACK);
    stopped->captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPED);
    PushBuf(inner, 1000, 4, 5000);
    PushBuf(mic, 2000, 4, 5100);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    src->SetCapture(AudioCaptureSourceType::APP_PLAYBACK, stopped);
    src->AcquireReady();
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
    EXPECT_EQ(mic->availBuffers_.size(), 0u);
}

// === Coverage: MixAudio empty ===

HWTEST_F(AudioDataSourceGenericTest, MixAudio_Empty_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    std::vector<const CacheBuffer *> srcs;
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
}

// === Coverage: SetMixAudioTypeLog ===

HWTEST_F(AudioDataSourceGenericTest, SetMixAudioTypeLog_Single_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->lastEmit_ = {AudioOutputTag::SINGLE, AudioCaptureSourceType::MIC, 100};
    src->SetMixAudioTypeLog(AudioOutputTag::SINGLE);
    EXPECT_EQ(src->logStats_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(src->logStats_.source, AudioCaptureSourceType::MIC);
}

HWTEST_F(AudioDataSourceGenericTest, SetMixAudioTypeLog_Mixed_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->SetMixAudioTypeLog(AudioOutputTag::MIXED);
    EXPECT_EQ(src->logStats_.type, AudioOutputTag::MIXED);
    EXPECT_EQ(src->logStats_.source, AudioCaptureSourceType::SOURCE_DEFAULT);
}

HWTEST_F(AudioDataSourceGenericTest, SetMixAudioTypeLog_Silent_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->SetMixAudioTypeLog(AudioOutputTag::SILENT);
    EXPECT_EQ(src->logStats_.type, AudioOutputTag::SILENT);
}

// === Coverage: LostFrameNum guards ===

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_NegativeTimestamp_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    EXPECT_EQ(src->LostFrameNum(-1), 0);
}

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_NegativeWritedTime_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = -1;
    src->pauseDuration_.store(0);
    EXPECT_EQ(src->LostFrameNum(0), 0);
}

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_NegativePauseDuration_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(-1);
    EXPECT_EQ(src->LostFrameNum(0), 0);
}

// === Coverage: GetSize with valid buffer ===

HWTEST_F(AudioDataSourceGenericTest, GetSize_ValidBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = MakeBuf(100, 4, 0);
    int64_t size = 0;
    EXPECT_EQ(src->GetSize(size), MSERR_OK);
    EXPECT_EQ(size, 8);
}

HWTEST_F(AudioDataSourceGenericTest, GetSize_ZeroLength_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto emptyData = std::make_unique<uint8_t[]>(0);
    src->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(emptyData), 0, 0);
    int64_t size = 0;
    EXPECT_EQ(src->GetSize(size), MSERR_UNKNOWN);
}

// === Coverage: Combine alloc fail (RETRY_SKIP path) ===
// Can't easily trigger alloc fail; skip.

// === Coverage: ReadAt with valid buffer ===

HWTEST_F(AudioDataSourceGenericTest, ReadAt_NullBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = MakeBuf(100, 4, 0);
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(src->ReadAt(buffer, 8), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_NullMemory_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = MakeBuf(100, 4, 0);
    auto buffer = std::make_shared<AVBuffer>();
    buffer->memory_ = nullptr;
    EXPECT_EQ(src->ReadAt(buffer, 8), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// === Coverage: LostFrameNum with gap (lostNum > 0) ===

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_LostFrames_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    EXPECT_EQ(src->LostFrameNum(3 * interval), 3);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_AudioSynced_NoCaptures_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->SetVideoFirstFramePts(1000);
    src->avSynced_ = true;
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

HWTEST_F(AudioDataSourceGenericTest, GetSize_NoBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    int64_t size = 0;
    EXPECT_EQ(src->GetSize(size), MSERR_UNKNOWN);
}

HWTEST_F(AudioDataSourceGenericTest, SetVideoFirstFramePts_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    EXPECT_EQ(src->firstVideoFramePts_.load(), -1);
    src->SetVideoFirstFramePts(12345);
    EXPECT_EQ(src->firstVideoFramePts_.load(), 12345);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_NoBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(src->ReadAt(buffer, 0), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_NullCaptureSlots_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::STABLE, nullptr, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::STABLE, nullptr, 0});
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// === MixAudio ===

HWTEST_F(AudioDataSourceGenericTest, MixAudio_TwoSource_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(1000, 4, 0);
    auto bufB = MakeBuf(2000, 4, 0);
    std::vector<const CacheBuffer *> srcs = {bufA.get(), bufB.get()};
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
    EXPECT_EQ(out[0], 3000);
    EXPECT_EQ(out[3], 3000);
}

HWTEST_F(AudioDataSourceGenericTest, MixAudio_ThreeSource_Overflow_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(32767, 4, 0);
    auto bufB = MakeBuf(32767, 4, 0);
    auto bufC = MakeBuf(32767, 4, 0);
    std::vector<const CacheBuffer *> srcs = {bufA.get(), bufB.get(), bufC.get()};
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
    for (int i = 0; i < 4; i++) {
        EXPECT_GE(out[i], -32768);
        EXPECT_LE(out[i], 32767);
    }
}

HWTEST_F(AudioDataSourceGenericTest, MixAudio_NegativeOverflow_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(-32768, 4, 0);
    auto bufB = MakeBuf(-32768, 4, 0);
    std::vector<const CacheBuffer *> srcs = {bufA.get(), bufB.get()};
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
    for (int i = 0; i < 4; i++) {
        EXPECT_GE(out[i], -32768);
        EXPECT_LE(out[i], 32767);
    }
}

// === Combine ===

HWTEST_F(AudioDataSourceGenericTest, Combine_SingleSource_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto buf = MakeBuf(100, 4, 5000);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, buf, 0});
    EXPECT_EQ(src->Combine(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->cacheBuffer_->timestamp, 5000);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(src->lastEmit_.source, AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::STABLE);
}

HWTEST_F(AudioDataSourceGenericTest, Combine_TwoSource_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(1000, 4, 5000);
    auto bufB = MakeBuf(2000, 4, 5100);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, bufA, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::UNSTABLE, bufB, 0});
    EXPECT_EQ(src->Combine(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->cacheBuffer_->timestamp, 5000);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::MIXED);
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::STABLE);
    EXPECT_EQ(src->captures_[1].state, CaptureSlotState::STABLE);
    auto *out = reinterpret_cast<const int16_t *>(src->cacheBuffer_->Data());
    EXPECT_EQ(out[0], 3000);
}

HWTEST_F(AudioDataSourceGenericTest, Combine_Empty_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    EXPECT_EQ(src->Combine(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// === AlignOrCombine ===

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_InWindow_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(1000, 4, 5000);
    auto bufB = MakeBuf(2000, 4, 5100);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, bufA, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::UNSTABLE, bufB, 0});
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::MIXED);
}

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_Stale_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    constexpr int64_t interval = 21333334;
    auto bufRef = MakeBuf(1000, 4, 5000);
    auto bufStale = MakeBuf(2000, 4, 5000 - 2 * interval);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, bufRef, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::UNSTABLE, bufStale, 0});
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(src->captures_[0].currentBuf, nullptr);
    EXPECT_EQ(src->captures_[1].currentBuf, nullptr);
}

// === Coverage: MixAudio with short buffer (length check) ===

HWTEST_F(AudioDataSourceGenericTest, MixAudio_ShortBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufLong = MakeBuf(1000, 4, 0);
    auto bufShort = MakeBuf(2000, 2, 0);
    std::vector<const CacheBuffer *> srcs = {bufLong.get(), bufShort.get()};
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
    EXPECT_EQ(out[0], 3000);
    EXPECT_EQ(out[1], 3000);
}

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_Ahead_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    constexpr int64_t interval = 21333334;
    auto bufRef = MakeBuf(1000, 4, 5000);
    auto bufAhead = MakeBuf(2000, 4, 5000 + 2 * interval);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, bufRef, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::UNSTABLE, bufAhead, 0});
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(src->captures_[1].currentBuf, nullptr);
}

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_StableSkipCheck_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    constexpr int64_t interval = 21333334;
    auto bufRef = MakeBuf(1000, 4, 5000);
    auto bufStable = MakeBuf(2000, 4, 5000 + 2 * interval);
    src->captures_.push_back({AudioCaptureSourceType::ALL_PLAYBACK, nullptr, CaptureSlotState::UNSTABLE, bufRef, 0});
    src->captures_.push_back({AudioCaptureSourceType::MIC, nullptr, CaptureSlotState::STABLE, bufStable, 0});
    EXPECT_EQ(src->AlignOrCombine(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::MIXED);
    EXPECT_EQ(src->captures_[1].currentBuf, nullptr);
}

// === LostFrameNum ===

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_NoLoss_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    EXPECT_EQ(src->LostFrameNum(0), 0);
}

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_OneFrame_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    EXPECT_EQ(src->LostFrameNum(interval), 1);
}

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_NegativePts_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    EXPECT_EQ(src->firstVideoFramePts_.load(), -1);
    EXPECT_EQ(src->LostFrameNum(1000), 0);
}

HWTEST_F(AudioDataSourceGenericTest, LostFrameNum_WithPause_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(interval);
    EXPECT_EQ(src->LostFrameNum(2 * interval), 1);
}

// === SetListener + OnBufferAvailable ===

HWTEST_F(AudioDataSourceGenericTest, SetListener_OnBufferReady_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto listener = std::make_shared<MockListener>();
    src->SetListener(listener);
    auto buf = MakeBuf(100, 4, 0);
    src->cacheBuffer_ = buf;
    src->OnBufferAvailable(AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(listener->count_, 1);
}

HWTEST_F(AudioDataSourceGenericTest, OnBufferAvailable_NoCacheBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto listener = std::make_shared<MockListener>();
    src->SetListener(listener);
    src->OnBufferAvailable(AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(listener->count_, 0);
}

// === SetCapture with real AudioCapturerWrapper ===

HWTEST_F(AudioDataSourceGenericTest, SetCapture_RegisterOne_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    EXPECT_EQ(src->captures_.size(), 1u);
    EXPECT_EQ(src->captures_[0].type, AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(src->captures_[0].capture, wrapper);
}

HWTEST_F(AudioDataSourceGenericTest, SetCapture_ReplaceExisting_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper1 = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto wrapper2 = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper1);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper2);
    EXPECT_EQ(src->captures_.size(), 1u);
    EXPECT_EQ(src->captures_[0].capture, wrapper2);
}

HWTEST_F(AudioDataSourceGenericTest, SetCapture_TwoSources_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->captures_.size(), 2u);
}

// === AcquireReady with real wrapper ===

HWTEST_F(AudioDataSourceGenericTest, AcquireReady_RecordingWithData_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(wrapper, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    EXPECT_TRUE(src->AcquireReady());
    EXPECT_NE(src->captures_[0].currentBuf, nullptr);
    EXPECT_EQ(src->captures_[0].currentBuf->timestamp, 5000);
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::UNSTABLE);
}

HWTEST_F(AudioDataSourceGenericTest, AcquireReady_NotRecording_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    wrapper->captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPED);
    PushBuf(wrapper, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    EXPECT_FALSE(src->AcquireReady());
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::INACTIVE);
    EXPECT_EQ(src->captures_[0].lastTs, 0);
}

HWTEST_F(AudioDataSourceGenericTest, AcquireReady_EmptyDeque_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    EXPECT_FALSE(src->AcquireReady());
}

HWTEST_F(AudioDataSourceGenericTest, AcquireReady_StableFrameLoss_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    PushBuf(wrapper, 1000, 4, 5000);
    src->AcquireReady();
    src->captures_[0].state = CaptureSlotState::STABLE;
    src->captures_[0].capture->ReleaseAudioBuffer();
    PushBuf(wrapper, 1000, 4, 5000 + 5 * 21333334);
    src->AcquireReady();
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::UNSTABLE);
}

HWTEST_F(AudioDataSourceGenericTest, AcquireReady_StableNormalGap_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    PushBuf(wrapper, 1000, 4, 5000);
    src->AcquireReady();
    src->captures_[0].state = CaptureSlotState::STABLE;
    src->captures_[0].capture->ReleaseAudioBuffer();
    PushBuf(wrapper, 1000, 4, 5000 + 21333334);
    src->AcquireReady();
    EXPECT_EQ(src->captures_[0].state, CaptureSlotState::STABLE);
}

// === ReadAudioBuffer full flow with wrapper ===

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_SingleSource_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(wrapper, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, wrapper);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->cacheBuffer_->timestamp, 5000);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(wrapper->availBuffers_.size(), 0u);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_TwoSourceMix_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 5000);
    PushBuf(mic, 2000, 4, 5100);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::MIXED);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
    EXPECT_EQ(mic->availBuffers_.size(), 0u);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_MicNotRecording_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    mic->captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPED);
    PushBuf(inner, 1000, 4, 5000);
    PushBuf(mic, 2000, 4, 5100);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAudioBuffer_MicRecording_NoBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
}

// === AlignOrCombine with real wrapper ===

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_StaleDropBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    constexpr int64_t interval = 21333334;
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 5000);
    PushBuf(mic, 2000, 4, 5000 - 2 * interval);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
}

HWTEST_F(AudioDataSourceGenericTest, AlignOrCombine_AheadReleaseInner_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    constexpr int64_t interval = 21333334;
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 5000);
    PushBuf(mic, 2000, 4, 5000 + 2 * interval);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
    EXPECT_EQ(mic->availBuffers_.size(), 1u);
}

// === VideoAudioSyncIfNeed ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_DropAhead_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    constexpr int64_t interval = 21333334;
    src->SetVideoFirstFramePts(10000 + 3 * interval);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    EXPECT_TRUE(src->avSynced_);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
}

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_InWindow_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetVideoFirstFramePts(10000);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_TRUE(src->avSynced_);
}

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_VideoBeforeAudio_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 100000000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    constexpr int64_t interval = 21333334;
    src->SetVideoFirstFramePts(100000000 - 3 * interval);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_TRUE(src->avSynced_);
}

// === PASSTHROUGH with wrapper ===

HWTEST_F(AudioDataSourceGenericTest, PASSTHROUGH_SingleSource_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::PASSTHROUGH, false);
    auto wrapper = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(wrapper, 1000, 4, 5000);
    src->SetCapture(AudioCaptureSourceType::MIC, wrapper);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    ASSERT_NE(src->cacheBuffer_, nullptr);
    EXPECT_EQ(src->lastEmit_.type, AudioOutputTag::SINGLE);
    EXPECT_EQ(wrapper->availBuffers_.size(), 0u);
}

// === Coverage: ReadAt with valid AVBuffer ===

HWTEST_F(AudioDataSourceGenericTest, ReadAt_ValidBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = MakeBuf(100, 4, 0);
    auto buffer = MakeAVBuffer(8);
    EXPECT_EQ(src->ReadAt(buffer, 8), AudioDataSourceReadAtActionState::OK);
    EXPECT_EQ(src->cacheBuffer_, nullptr);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_LostFrames_SilentFill_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    src->cacheBuffer_ = MakeBuf(100, 4, 3 * interval);
    auto buffer = MakeAVBuffer(8);
    EXPECT_EQ(src->ReadAt(buffer, 8), AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_SilentFill_ReuseZeroBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    src->firstVideoFramePts_.store(0);
    src->writedFrameTime_ = 0;
    src->pauseDuration_.store(0);
    src->cacheBuffer_ = MakeBuf(100, 4, 3 * interval);
    auto buffer1 = MakeAVBuffer(8);
    src->ReadAt(buffer1, 8);
    src->cacheBuffer_ = MakeBuf(100, 4, 6 * interval);
    auto buffer2 = MakeAVBuffer(8);
    EXPECT_EQ(src->ReadAt(buffer2, 8), AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_WriteToFail_NullOwnedBuf_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = std::make_shared<CacheBuffer>(std::unique_ptr<uint8_t[]>(nullptr), 8, 0);
    auto buffer = MakeAVBuffer(8);
    EXPECT_EQ(src->ReadAt(buffer, 8), AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(AudioDataSourceGenericTest, ReadAt_WriteToFail_ReuseZeroBuffer_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->cacheBuffer_ = std::make_shared<CacheBuffer>(std::unique_ptr<uint8_t[]>(nullptr), 8, 0);
    auto buffer1 = MakeAVBuffer(8);
    src->ReadAt(buffer1, 8);
    src->cacheBuffer_ = std::make_shared<CacheBuffer>(std::unique_ptr<uint8_t[]>(nullptr), 8, 0);
    auto buffer2 = MakeAVBuffer(8);
    EXPECT_EQ(src->ReadAt(buffer2, 8), AudioDataSourceReadAtActionState::OK);
}

// === Coverage: MixAudio with null src and varying lengths ===

HWTEST_F(AudioDataSourceGenericTest, MixAudio_NullSrc_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto bufA = MakeBuf(1000, 4, 0);
    std::vector<const CacheBuffer *> srcs = {bufA.get(), nullptr};
    int16_t out[4] = {0};
    src->MixAudio(srcs, reinterpret_cast<uint8_t *>(out));
    EXPECT_EQ(out[0], 1000);
}

// === Coverage: LogStats::Update same type different source ===

HWTEST_F(AudioDataSourceGenericTest, LogStats_UpdateSameTypeDiffSrc_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    src->logStats_.Update(AudioOutputTag::SINGLE, AudioCaptureSourceType::ALL_PLAYBACK);
    src->logStats_.Update(AudioOutputTag::SINGLE, AudioCaptureSourceType::MIC);
    EXPECT_EQ(src->logStats_.source, AudioCaptureSourceType::MIC);
}

// === Coverage: OnBufferAvailable ReadAudioBuffer not OK ===

HWTEST_F(AudioDataSourceGenericTest, OnBufferAvailable_ReadNotOK_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, false);
    auto listener = std::make_shared<MockListener>();
    src->SetListener(listener);
    src->OnBufferAvailable(AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(listener->count_, 0);
}

// === Coverage: VideoAudioSyncIfNeed multiple slots ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_MultipleSlots_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    PushBuf(inner, 1000, 4, 20000);
    PushBuf(mic, 2000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    src->SetVideoFirstFramePts(10000);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::OK);
    EXPECT_TRUE(src->avSynced_);
}

// === Coverage: VideoAudioSyncIfNeed direct call, no currentBuf ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSyncIfNeed_NoCurrentBuf_Direct_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    src->SetVideoFirstFramePts(1000);
    EXPECT_EQ(src->VideoAudioSyncIfNeed(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// === Coverage: VideoAudioSyncIfNeed DropBufferUntil with null capture ===

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_DropAhead_MixedSlots_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    auto mic = MakeMockWrapper(AudioCaptureSourceType::MIC);
    auto stopped = MakeMockWrapper(AudioCaptureSourceType::APP_PLAYBACK);
    stopped->captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPED);
    PushBuf(inner, 1000, 4, 10000);
    PushBuf(mic, 2000, 4, 20000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetCapture(AudioCaptureSourceType::MIC, mic);
    src->SetCapture(AudioCaptureSourceType::APP_PLAYBACK, stopped);
    src->SetVideoFirstFramePts(10000 + 3 * interval);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    EXPECT_TRUE(src->avSynced_);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
    EXPECT_EQ(mic->availBuffers_.size(), 0u);
}

HWTEST_F(AudioDataSourceGenericTest, VideoAudioSync_DropNullCapture_001, TestSize.Level2)
{
    auto src = std::make_shared<AudioDataSourceGeneric>(AudioCombinePolicy::MIX_ALL, true);
    constexpr int64_t interval = 21333334;
    auto inner = MakeMockWrapper(AudioCaptureSourceType::ALL_PLAYBACK);
    PushBuf(inner, 1000, 4, 10000);
    src->SetCapture(AudioCaptureSourceType::ALL_PLAYBACK, inner);
    src->SetVideoFirstFramePts(10000 + 3 * interval);
    EXPECT_EQ(src->ReadAudioBuffer(), AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    EXPECT_TRUE(src->avSynced_);
    EXPECT_EQ(inner->availBuffers_.size(), 0u);
}

} // namespace Media
} // namespace OHOS
