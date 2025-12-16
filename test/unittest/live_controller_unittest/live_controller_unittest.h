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

#ifndef LIVE_CONTROLLER_UNITTEST_H
#define LIVE_CONTROLLER_UNITTEST_H

#include "gtest/gtest.h"
#include "live_controller.h"
#include <gmock/gmock.h>
#include "osal/utils/steady_clock.h"

namespace OHOS {
namespace Media {
class LiveControllerUnittest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
protected:
    std::unique_ptr<LiveController> liveController_{nullptr};
};
class MockIPlayerEngineObs : public IPlayerEngineObs {
public:
    MockIPlayerEngineObs() = default;
    ~MockIPlayerEngineObs() override = default;
    MOCK_METHOD(void, OnError, (PlayerErrorType errorType, int32_t errorCode, const std::string &description), ());
    MOCK_METHOD(void, OnErrorMessage, (int32_t errorCode, const std::string &errorMsg), ());
    MOCK_METHOD(void, OnInfo, (PlayerOnInfoType type, int32_t extra, const Format &infoBody), ());
    MOCK_METHOD(void, OnSystemOperation,
        (PlayerOnSystemOperationType type, PlayerOperationReason reason), ());
};
class MockIPlayerEngine : public IPlayerEngine {
public:
    MockIPlayerEngine() = default;
    ~MockIPlayerEngine() override = default;
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::shared_ptr<IMediaDataSource> &dataSrc), (override));
    MOCK_METHOD(int32_t, SetObs, (const std::weak_ptr<IPlayerEngineObs> &obs), (override));
    MOCK_METHOD(int32_t, AddSubSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, Play, (), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, SetRenderFirstFrame, (bool display), (override));
    MOCK_METHOD(int32_t, SetPlayRange, (int64_t start, int64_t end), (override));
    MOCK_METHOD(int32_t, SetPlayRangeWithMode, (int64_t start, int64_t end, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, PrepareAsync, (), (override));
    MOCK_METHOD(int32_t, Pause, (bool isSystemOperation), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, SetVolume, (float leftVolume, float rightVolume), (override));
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), (override));
    MOCK_METHOD(int32_t, Seek, (int32_t mSeconds, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), (override));
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), (override));
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), (override));
    MOCK_METHOD(int32_t, GetPlaybackStatisticMetrics, (Format &playbackStatisticMetrics), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), (override));
    MOCK_METHOD(int32_t, GetVideoWidth, (), (override));
    MOCK_METHOD(int32_t, GetVideoHeight, (), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), (override));
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), (override));
    MOCK_METHOD(int32_t, SetMediaSource, (const std::shared_ptr<AVMediaSource> &mediaSource,
        AVPlayStrategy strategy), (override));
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate, bool isAutoSelect), (override));
    MOCK_METHOD(int32_t, SetDecryptConfig, (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp), (override));
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface), (override));
    MOCK_METHOD(float, GetMaxAmplitude, (), (override));
    MOCK_METHOD(int32_t, SetLooping, (bool loop), (override));
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), (override));
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), (override));
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), (override));
    MOCK_METHOD(int32_t, SetPlaybackStrategy, (AVPlayStrategy playbackStrategy), (override));
    MOCK_METHOD(int64_t, GetPlayRangeEndTime, (), (override));
    MOCK_METHOD(int32_t, SetMaxAmplitudeCbStatus, (bool status), (override));
    MOCK_METHOD(int32_t, Freeze, (bool &isNoNeedToFreeze), (override));
    MOCK_METHOD(int32_t, UnFreeze, (), (override));
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), (override));
};
class MockTask : public Task {
public:
    explicit MockTask(const std::string& name, const std::string& groupId = "", TaskType type = TaskType::SINGLETON,
        TaskPriority priority = TaskPriority::NORMAL, bool singleLoop = true):Task(name, groupId, type,
        priority, singleLoop) {}
    MOCK_METHOD(void, SubmitJob,
        (const std::function<void()>& job, int64_t delayUs, bool wait), (override));
};
} // namespace Media
} // namespace OHOS
#endif // LIVE_CONTROLLER_UNIT_TEST_H