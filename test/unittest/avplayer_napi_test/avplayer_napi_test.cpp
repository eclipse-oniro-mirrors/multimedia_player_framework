/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "avplayer_napi_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void AVPlayerNapiTest::SetUp()
{
    jsPlayer_ = new AVPlayerNapi();
    player_ = std::make_shared<FakePlayer>();
    jsPlayer_->player_ = player_;
    jsPlayer_->taskQue_ = std::make_unique<TaskQueue>("AVPlayerNapiUnitTest");
    (void)jsPlayer_->taskQue_->Start();
    jsPlayer_->avplayerExit_ = true;
}

void AVPlayerNapiTest::TearDown()
{
    if (jsPlayer_ != nullptr) {
        if (jsPlayer_->taskQue_ != nullptr) {
            jsPlayer_->StopTaskQue();
        }
        delete jsPlayer_;
        jsPlayer_ = nullptr;
    }
    player_ = nullptr;
}

void AVPlayerNapiTest::SyncTaskQueue()
{
    if (jsPlayer_ == nullptr || jsPlayer_->taskQue_ == nullptr) {
        return;
    }
    auto sentinel = std::make_shared<TaskHandler<int32_t>>([]() -> int32_t { return MSERR_OK; });
    (void)jsPlayer_->taskQue_->EnqueueTask(sentinel);
    (void)sentinel->GetResult();
}

void AVPlayerNapiTest::SetState(PlayerStates state)
{
    jsPlayer_->isReleased_.store(false);
    jsPlayer_->state_ = state;
}

static TaskRet GetTaskResultValue(const std::shared_ptr<TaskHandler<TaskRet>> &task)
{
    auto result = task->GetResult();
    EXPECT_TRUE(result.HasResult());
    return result.Value();
}

HWTEST_F(AVPlayerNapiTest, StateConstants_001, TestSize.Level0)
{
    EXPECT_EQ(AVPlayerState::STATE_IDLE, "idle");
    EXPECT_EQ(AVPlayerState::STATE_INITIALIZED, "initialized");
    EXPECT_EQ(AVPlayerState::STATE_PREPARED, "prepared");
    EXPECT_EQ(AVPlayerState::STATE_PLAYING, "playing");
    EXPECT_EQ(AVPlayerState::STATE_PAUSED, "paused");
    EXPECT_EQ(AVPlayerState::STATE_STOPPED, "stopped");
    EXPECT_EQ(AVPlayerState::STATE_RELEASED, "released");
    EXPECT_EQ(AVPlayerState::STATE_ERROR, "error");
    EXPECT_EQ(AVPlayerState::STATE_COMPLETED, "completed");
}

HWTEST_F(AVPlayerNapiTest, EventConstants_001, TestSize.Level0)
{
    EXPECT_EQ(AVPlayerEvent::EVENT_STATE_CHANGE, "stateChange");
    EXPECT_EQ(AVPlayerEvent::EVENT_VOLUME_CHANGE, "volumeChange");
    EXPECT_EQ(AVPlayerEvent::EVENT_END_OF_STREAM, "endOfStream");
    EXPECT_EQ(AVPlayerEvent::EVENT_SEEK_DONE, "seekDone");
    EXPECT_EQ(AVPlayerEvent::EVENT_SPEED_DONE, "speedDone");
    EXPECT_EQ(AVPlayerEvent::EVENT_RATE_DONE, "playbackRateDone");
    EXPECT_EQ(AVPlayerEvent::EVENT_BITRATE_DONE, "bitrateDone");
    EXPECT_EQ(AVPlayerEvent::EVENT_TIME_UPDATE, "timeUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_DURATION_UPDATE, "durationUpdate");
}

HWTEST_F(AVPlayerNapiTest, EventConstants_002, TestSize.Level0)
{
    EXPECT_EQ(AVPlayerEvent::EVENT_SUBTITLE_TEXT_UPDATE, "subtitleTextUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_BUFFERING_UPDATE, "bufferingUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_START_RENDER_FRAME, "startRenderFrame");
    EXPECT_EQ(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE, "videoSizeChange");
    EXPECT_EQ(AVPlayerEvent::EVENT_AUDIO_INTERRUPT, "audioInterrupt");
    EXPECT_EQ(AVPlayerEvent::EVENT_AVAILABLE_BITRATES, "availableBitrates");
    EXPECT_EQ(AVPlayerEvent::EVENT_TRACKCHANGE, "trackChange");
    EXPECT_EQ(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE, "trackInfoUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_DRM_INFO_UPDATE, "mediaKeySystemInfoUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE, "setDecryptConfigDone");
}

HWTEST_F(AVPlayerNapiTest, EventConstants_003, TestSize.Level0)
{
    EXPECT_EQ(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE, "audioOutputDeviceChangeWithInfo");
    EXPECT_EQ(AVPlayerEvent::EVENT_SUBTITLE_UPDATE, "subtitleUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_ERROR, "error");
    EXPECT_EQ(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE, "amplitudeUpdate");
    EXPECT_EQ(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO, "seiMessageReceived");
    EXPECT_EQ(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED, "superResolutionChanged");
    EXPECT_EQ(AVPlayerEvent::EVENT_METRICS, "metricsEvent");
    EXPECT_EQ(AVPlayerEvent::EVENT_PLAYBACK_CONTENT_CHANGE, "playbackContentChange");
    EXPECT_EQ(AVPlayerEvent::EVENT_TIMED_META_DATA, "timedMetaData");
}

HWTEST_F(AVPlayerNapiTest, EventConstants_004, TestSize.Level0)
{
    EXPECT_EQ(AVPlayerEvent::EVENT_ADS_LOADING_ERROR, "adsLoadingError");
    EXPECT_EQ(AVPlayerEvent::EVENT_ADS_STARTED, "adsStarted");
    EXPECT_EQ(AVPlayerEvent::EVENT_ADS_SKIPPED, "adsSkipped");
    EXPECT_EQ(AVPlayerEvent::EVENT_ADS_COMPLETED, "adsCompleted");
}

HWTEST_F(AVPlayerNapiTest, GetCurrentState_Mapping_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "idle");
    SetState(PLAYER_INITIALIZED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "initialized");
    SetState(PLAYER_PREPARED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "prepared");
    SetState(PLAYER_STARTED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "playing");
    SetState(PLAYER_PAUSED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "paused");
}

HWTEST_F(AVPlayerNapiTest, GetCurrentState_Mapping_002, TestSize.Level0)
{
    SetState(PLAYER_STOPPED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "stopped");
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "completed");
    SetState(PLAYER_STATE_ERROR);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "error");
}

HWTEST_F(AVPlayerNapiTest, GetCurrentState_UnmappedStates_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARING);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "error");
    SetState(PLAYER_RELEASED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "error");
    SetState(PLAYER_FROZEN);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "error");
}

HWTEST_F(AVPlayerNapiTest, GetCurrentState_Released_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    jsPlayer_->isReleased_.store(true);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "released");
    jsPlayer_->isReleased_.store(false);
}

HWTEST_F(AVPlayerNapiTest, NotifyState_ChangesState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->NotifyState(PLAYER_PREPARED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "prepared");
}

HWTEST_F(AVPlayerNapiTest, NotifyState_SameState_NoChange_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    jsPlayer_->stopWait_ = false;
    jsPlayer_->NotifyState(PLAYER_PREPARED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "prepared");
    EXPECT_FALSE(jsPlayer_->stopWait_);
}

HWTEST_F(AVPlayerNapiTest, NotifyState_DifferentState_SetStopWait_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    jsPlayer_->stopWait_ = false;
    jsPlayer_->NotifyState(PLAYER_STARTED);
    EXPECT_EQ(jsPlayer_->GetCurrentState(), "playing");
    EXPECT_TRUE(jsPlayer_->stopWait_);
}

HWTEST_F(AVPlayerNapiTest, IsControllable_StateMatrix_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->IsControllable());
    SetState(PLAYER_STARTED);
    EXPECT_TRUE(jsPlayer_->IsControllable());
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(jsPlayer_->IsControllable());
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(jsPlayer_->IsControllable());
}

HWTEST_F(AVPlayerNapiTest, IsControllable_StateMatrix_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->IsControllable());
    SetState(PLAYER_INITIALIZED);
    EXPECT_FALSE(jsPlayer_->IsControllable());
    SetState(PLAYER_STOPPED);
    EXPECT_FALSE(jsPlayer_->IsControllable());
    SetState(PLAYER_STATE_ERROR);
    EXPECT_FALSE(jsPlayer_->IsControllable());
    SetState(PLAYER_PREPARING);
    EXPECT_FALSE(jsPlayer_->IsControllable());
    SetState(PLAYER_FROZEN);
    EXPECT_FALSE(jsPlayer_->IsControllable());
}

HWTEST_F(AVPlayerNapiTest, CanGetPlaybackStatisticMetrics_StateMatrix_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_STARTED);
    EXPECT_TRUE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_STOPPED);
    EXPECT_TRUE(jsPlayer_->CanGetPlaybackStatisticMetrics());
}

HWTEST_F(AVPlayerNapiTest, CanGetPlaybackStatisticMetrics_StateMatrix_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_INITIALIZED);
    EXPECT_FALSE(jsPlayer_->CanGetPlaybackStatisticMetrics());
    SetState(PLAYER_STATE_ERROR);
    EXPECT_FALSE(jsPlayer_->CanGetPlaybackStatisticMetrics());
}

HWTEST_F(AVPlayerNapiTest, CanSetPlayRange_StateMatrix_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    EXPECT_TRUE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_STOPPED);
    EXPECT_TRUE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(jsPlayer_->CanSetPlayRange());
}

HWTEST_F(AVPlayerNapiTest, CanSetPlayRange_StateMatrix_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_STARTED);
    EXPECT_FALSE(jsPlayer_->CanSetPlayRange());
    SetState(PLAYER_STATE_ERROR);
    EXPECT_FALSE(jsPlayer_->CanSetPlayRange());
}

HWTEST_F(AVPlayerNapiTest, CanSetSuperResolution_StateMatrix_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_STARTED);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_STOPPED);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(jsPlayer_->CanSetSuperResolution());
}

HWTEST_F(AVPlayerNapiTest, CanSetSuperResolution_StateMatrix_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CanSetSuperResolution());
    SetState(PLAYER_STATE_ERROR);
    EXPECT_FALSE(jsPlayer_->CanSetSuperResolution());
}

HWTEST_F(AVPlayerNapiTest, CanCameraPostprocessing_OnlyInitialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    EXPECT_TRUE(jsPlayer_->CanCameraPostprocessing());
}

HWTEST_F(AVPlayerNapiTest, CanCameraPostprocessing_OnlyInitialized_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CanCameraPostprocessing());
    SetState(PLAYER_PREPARED);
    EXPECT_FALSE(jsPlayer_->CanCameraPostprocessing());
    SetState(PLAYER_STARTED);
    EXPECT_FALSE(jsPlayer_->CanCameraPostprocessing());
    SetState(PLAYER_STOPPED);
    EXPECT_FALSE(jsPlayer_->CanCameraPostprocessing());
}

HWTEST_F(AVPlayerNapiTest, CanSetLoudnessGain_StateMatrix_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_STARTED);
    EXPECT_TRUE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_STOPPED);
    EXPECT_TRUE(jsPlayer_->CanSetLoudnessGain());
}

HWTEST_F(AVPlayerNapiTest, CanSetLoudnessGain_StateMatrix_002, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_INITIALIZED);
    EXPECT_FALSE(jsPlayer_->CanSetLoudnessGain());
    SetState(PLAYER_STATE_ERROR);
    EXPECT_FALSE(jsPlayer_->CanSetLoudnessGain());
}

HWTEST_F(AVPlayerNapiTest, CheckControllableState_Controllable_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(jsPlayer_->CheckControllableState(jsPlayer_, "seek"));
}

HWTEST_F(AVPlayerNapiTest, CheckControllableState_Uncontrollable_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CheckControllableState(jsPlayer_, "seek"));
}

HWTEST_F(AVPlayerNapiTest, CheckControllableState_NullPlayerCb_NoCrash_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(jsPlayer_->CheckControllableState(jsPlayer_, "setVolume"));
}

HWTEST_F(AVPlayerNapiTest, TransferSeekMode_AllModes_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->TransferSeekMode(0), PlayerSeekMode::SEEK_NEXT_SYNC);
    EXPECT_EQ(jsPlayer_->TransferSeekMode(1), PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(jsPlayer_->TransferSeekMode(2), PlayerSeekMode::SEEK_CLOSEST);
    EXPECT_EQ(jsPlayer_->TransferSeekMode(3), PlayerSeekMode::SEEK_CONTINOUS);
}

HWTEST_F(AVPlayerNapiTest, TransferSeekMode_InvalidModes_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->TransferSeekMode(-1), PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(jsPlayer_->TransferSeekMode(4), PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(jsPlayer_->TransferSeekMode(100), PlayerSeekMode::SEEK_PREVIOUS_SYNC);
}

HWTEST_F(AVPlayerNapiTest, TransferSwitchMode_AllModes_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->TransferSwitchMode(0), PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(jsPlayer_->TransferSwitchMode(1), PlayerSwitchMode::SWITCH_SEGMENT);
}

HWTEST_F(AVPlayerNapiTest, TransferSwitchMode_InvalidModes_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->TransferSwitchMode(2), PlayerSwitchMode::SWITCH_CLOSEST);
    EXPECT_EQ(jsPlayer_->TransferSwitchMode(-1), PlayerSwitchMode::SWITCH_CLOSEST);
}

HWTEST_F(AVPlayerNapiTest, IsRateValid_ValidValues_001, TestSize.Level0)
{
    EXPECT_TRUE(jsPlayer_->IsRateValid(0.125f));
    EXPECT_TRUE(jsPlayer_->IsRateValid(1.0f));
    EXPECT_TRUE(jsPlayer_->IsRateValid(4.0f));
    EXPECT_TRUE(jsPlayer_->IsRateValid(8.0f));
    EXPECT_TRUE(jsPlayer_->IsRateValid(0.5f));
}

HWTEST_F(AVPlayerNapiTest, IsRateValid_InvalidValues_001, TestSize.Level0)
{
    EXPECT_FALSE(jsPlayer_->IsRateValid(0.0f));
    EXPECT_FALSE(jsPlayer_->IsRateValid(0.1f));
    EXPECT_FALSE(jsPlayer_->IsRateValid(-1.0f));
    EXPECT_FALSE(jsPlayer_->IsRateValid(9.0f));
    EXPECT_FALSE(jsPlayer_->IsRateValid(100.0f));
}

HWTEST_F(AVPlayerNapiTest, IsPalyingDurationValid_ValidCases_001, TestSize.Level0)
{
    AVPlayStrategyTmp tmp {};
    tmp.preferredBufferDuration = 10;
    tmp.preferredBufferDurationForPlaying = 5;
    EXPECT_TRUE(jsPlayer_->IsPalyingDurationValid(tmp));

    AVPlayStrategyTmp zeroBuffer {};
    zeroBuffer.preferredBufferDuration = 0;
    zeroBuffer.preferredBufferDurationForPlaying = 20;
    EXPECT_TRUE(jsPlayer_->IsPalyingDurationValid(zeroBuffer));
}

HWTEST_F(AVPlayerNapiTest, IsPalyingDurationValid_InvalidCases_001, TestSize.Level0)
{
    AVPlayStrategyTmp larger {};
    larger.preferredBufferDuration = 10;
    larger.preferredBufferDurationForPlaying = 20;
    EXPECT_FALSE(jsPlayer_->IsPalyingDurationValid(larger));

    AVPlayStrategyTmp negative {};
    negative.preferredBufferDuration = 10;
    negative.preferredBufferDurationForPlaying = -1;
    EXPECT_FALSE(jsPlayer_->IsPalyingDurationValid(negative));
}

HWTEST_F(AVPlayerNapiTest, IsLivingMaxDelayTimeValid_NotSet_001, TestSize.Level0)
{
    AVPlayStrategyTmp tmp {};
    tmp.isSetThresholdForAutoQuickPlay = false;
    EXPECT_TRUE(jsPlayer_->IsLivingMaxDelayTimeValid(tmp));
}

HWTEST_F(AVPlayerNapiTest, IsLivingMaxDelayTimeValid_InvalidCases_001, TestSize.Level0)
{
    AVPlayStrategyTmp smallThreshold {};
    smallThreshold.isSetThresholdForAutoQuickPlay = true;
    smallThreshold.thresholdForAutoQuickPlay = 1.0;
    EXPECT_FALSE(jsPlayer_->IsLivingMaxDelayTimeValid(smallThreshold));

    AVPlayStrategyTmp lessThanPlaying {};
    lessThanPlaying.isSetThresholdForAutoQuickPlay = true;
    lessThanPlaying.thresholdForAutoQuickPlay = 5.0;
    lessThanPlaying.preferredBufferDurationForPlaying = 10.0;
    EXPECT_FALSE(jsPlayer_->IsLivingMaxDelayTimeValid(lessThanPlaying));
}

HWTEST_F(AVPlayerNapiTest, IsLivingMaxDelayTimeValid_ValidCases_001, TestSize.Level0)
{
    AVPlayStrategyTmp valid {};
    valid.isSetThresholdForAutoQuickPlay = true;
    valid.thresholdForAutoQuickPlay = 5.0;
    valid.preferredBufferDurationForPlaying = 3.0;
    EXPECT_TRUE(jsPlayer_->IsLivingMaxDelayTimeValid(valid));

    AVPlayStrategyTmp minEdge {};
    minEdge.isSetThresholdForAutoQuickPlay = true;
    minEdge.thresholdForAutoQuickPlay = 2.0;
    minEdge.preferredBufferDurationForPlaying = 0;
    EXPECT_TRUE(jsPlayer_->IsLivingMaxDelayTimeValid(minEdge));
}

HWTEST_F(AVPlayerNapiTest, GetAVPlayStrategyFromStrategyTmp_FullMapping_001, TestSize.Level0)
{
    AVPlayStrategyTmp tmp {};
    tmp.preferredWidth = 1920;
    tmp.preferredHeight = 1080;
    tmp.preferredBufferDuration = 20;
    tmp.preferredHdr = true;
    tmp.showFirstFrameOnPrepare = true;
    tmp.enableSuperResolution = true;
    tmp.enableCameraPostprocessing = true;
    tmp.mutedMediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_AUD);
    tmp.preferredAudioLanguage = "zh";
    tmp.preferredSubtitleLanguage = "en";
    tmp.preferredBufferDurationForPlaying = 2.5;
    tmp.isSetBufferDurationForPlaying = true;
    tmp.thresholdForAutoQuickPlay = 5.0;
    tmp.isSetThresholdForAutoQuickPlay = true;
    tmp.keepDecodingOnMute = true;

    AVPlayStrategy strategy {};
    jsPlayer_->GetAVPlayStrategyFromStrategyTmp(strategy, tmp);

    EXPECT_EQ(strategy.preferredWidth, 1920u);
    EXPECT_EQ(strategy.preferredHeight, 1080u);
    EXPECT_EQ(strategy.preferredBufferDuration, 20u);
    EXPECT_TRUE(strategy.preferredHdr);
    EXPECT_TRUE(strategy.showFirstFrameOnPrepare);
    EXPECT_TRUE(strategy.enableSuperResolution);
    EXPECT_TRUE(strategy.enableCameraPostprocessing);
    EXPECT_EQ(strategy.mutedMediaType, MediaType::MEDIA_TYPE_AUD);
    EXPECT_EQ(strategy.preferredAudioLanguage, "zh");
    EXPECT_EQ(strategy.preferredSubtitleLanguage, "en");
    EXPECT_DOUBLE_EQ(strategy.preferredBufferDurationForPlaying, 2.5);
    EXPECT_DOUBLE_EQ(strategy.thresholdForAutoQuickPlay, 5.0);
    EXPECT_TRUE(strategy.keepDecodingOnMute);
}

HWTEST_F(AVPlayerNapiTest, GetAVPlayStrategyFromStrategyTmp_UnsetDefaults_001, TestSize.Level0)
{
    AVPlayStrategyTmp tmp {};
    AVPlayStrategy strategy {};
    jsPlayer_->GetAVPlayStrategyFromStrategyTmp(strategy, tmp);

    EXPECT_DOUBLE_EQ(strategy.preferredBufferDurationForPlaying, -1);
    EXPECT_DOUBLE_EQ(strategy.thresholdForAutoQuickPlay, -1);
    EXPECT_FALSE(strategy.enableSuperResolution);
    EXPECT_FALSE(strategy.enableCameraPostprocessing);
    EXPECT_TRUE(strategy.preferredAudioLanguage.empty());
}

HWTEST_F(AVPlayerNapiTest, NotifyDuration_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->duration_, -1);
    jsPlayer_->NotifyDuration(30000);
    EXPECT_EQ(jsPlayer_->duration_, 30000);
}

HWTEST_F(AVPlayerNapiTest, NotifyPosition_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->position_, -1);
    jsPlayer_->NotifyPosition(1200);
    EXPECT_EQ(jsPlayer_->position_, 1200);
}

HWTEST_F(AVPlayerNapiTest, NotifyVideoSize_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->width_, 0);
    EXPECT_EQ(jsPlayer_->height_, 0);
    jsPlayer_->NotifyVideoSize(1280, 720);
    EXPECT_EQ(jsPlayer_->width_, 1280);
    EXPECT_EQ(jsPlayer_->height_, 720);
}

HWTEST_F(AVPlayerNapiTest, NotifyIsLiveStream_001, TestSize.Level0)
{
    EXPECT_FALSE(jsPlayer_->IsLiveSource());
    jsPlayer_->NotifyIsLiveStream();
    EXPECT_TRUE(jsPlayer_->IsLiveSource());
    EXPECT_TRUE(jsPlayer_->isLiveStream_);
}

HWTEST_F(AVPlayerNapiTest, NotifyIsFlvLive_001, TestSize.Level0)
{
    EXPECT_FALSE(jsPlayer_->isFlvLive_);
    jsPlayer_->NotifyIsFlvLive(true);
    EXPECT_TRUE(jsPlayer_->isFlvLive_);
    jsPlayer_->NotifyIsFlvLive(false);
    EXPECT_FALSE(jsPlayer_->isFlvLive_);
}

HWTEST_F(AVPlayerNapiTest, NotifyDrmInfoUpdated_NewKey_001, TestSize.Level0)
{
    std::multimap<std::string, std::vector<uint8_t>> infos;
    infos.insert({"uuid1", {1, 2, 3}});
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    EXPECT_EQ(jsPlayer_->localDrmInfos_.size(), static_cast<size_t>(1));
}

HWTEST_F(AVPlayerNapiTest, NotifyDrmInfoUpdated_DuplicateIgnored_001, TestSize.Level0)
{
    std::multimap<std::string, std::vector<uint8_t>> infos;
    infos.insert({"uuid1", {1, 2, 3}});
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    EXPECT_EQ(jsPlayer_->localDrmInfos_.size(), static_cast<size_t>(1));
}

HWTEST_F(AVPlayerNapiTest, NotifyDrmInfoUpdated_SameKeyDifferentValue_001, TestSize.Level0)
{
    std::multimap<std::string, std::vector<uint8_t>> infos;
    infos.insert({"uuid1", {1, 2, 3}});
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    infos.insert({"uuid1", {4, 5}});
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    EXPECT_EQ(jsPlayer_->localDrmInfos_.size(), static_cast<size_t>(2));
}

HWTEST_F(AVPlayerNapiTest, NotifyDrmInfoUpdated_Empty_001, TestSize.Level0)
{
    std::multimap<std::string, std::vector<uint8_t>> infos;
    jsPlayer_->NotifyDrmInfoUpdated(infos);
    EXPECT_TRUE(jsPlayer_->localDrmInfos_.empty());
}

HWTEST_F(AVPlayerNapiTest, SaveCallbackReference_001, TestSize.Level0)
{
    auto ref = std::make_shared<AutoRef>(nullptr, nullptr);
    jsPlayer_->SaveCallbackReference("stateChange", ref);
    EXPECT_EQ(jsPlayer_->refMap_.size(), static_cast<size_t>(1));
    EXPECT_EQ(jsPlayer_->refMap_["stateChange"], ref);
}

HWTEST_F(AVPlayerNapiTest, SaveCallbackReference_Overwrite_001, TestSize.Level0)
{
    auto ref1 = std::make_shared<AutoRef>(nullptr, nullptr);
    auto ref2 = std::make_shared<AutoRef>(nullptr, nullptr);
    jsPlayer_->SaveCallbackReference("seekDone", ref1);
    jsPlayer_->SaveCallbackReference("seekDone", ref2);
    EXPECT_EQ(jsPlayer_->refMap_.size(), static_cast<size_t>(1));
    EXPECT_EQ(jsPlayer_->refMap_["seekDone"], ref2);
}

HWTEST_F(AVPlayerNapiTest, ClearCallbackReference_ByName_001, TestSize.Level0)
{
    auto ref1 = std::make_shared<AutoRef>(nullptr, nullptr);
    auto ref2 = std::make_shared<AutoRef>(nullptr, nullptr);
    jsPlayer_->SaveCallbackReference("stateChange", ref1);
    jsPlayer_->SaveCallbackReference("error", ref2);
    jsPlayer_->ClearCallbackReference("stateChange");
    EXPECT_EQ(jsPlayer_->refMap_.size(), static_cast<size_t>(1));
    EXPECT_EQ(jsPlayer_->refMap_.count("stateChange"), static_cast<size_t>(0));
    EXPECT_EQ(jsPlayer_->refMap_.count("error"), static_cast<size_t>(1));
}

HWTEST_F(AVPlayerNapiTest, ClearCallbackReference_All_001, TestSize.Level0)
{
    auto ref1 = std::make_shared<AutoRef>(nullptr, nullptr);
    auto ref2 = std::make_shared<AutoRef>(nullptr, nullptr);
    jsPlayer_->SaveCallbackReference("stateChange", ref1);
    jsPlayer_->SaveCallbackReference("error", ref2);
    jsPlayer_->ClearCallbackReference();
    EXPECT_TRUE(jsPlayer_->refMap_.empty());
}

HWTEST_F(AVPlayerNapiTest, ClearCallbackReference_NonexistentName_001, TestSize.Level0)
{
    jsPlayer_->ClearCallbackReference("notExist");
    EXPECT_TRUE(jsPlayer_->refMap_.empty());
}

HWTEST_F(AVPlayerNapiTest, HandleListenerStateChange_Amplitude_001, TestSize.Level0)
{
    jsPlayer_->HandleListenerStateChange("amplitudeUpdate", true);
    EXPECT_EQ(player_->amplitudeCnt_.load(), 1);
    EXPECT_TRUE(player_->lastAmplitudeStatus_);
    jsPlayer_->HandleListenerStateChange("amplitudeUpdate", false);
    EXPECT_EQ(player_->amplitudeCnt_.load(), 2);
    EXPECT_FALSE(player_->lastAmplitudeStatus_);
}

HWTEST_F(AVPlayerNapiTest, HandleListenerStateChange_TimeUpdate_001, TestSize.Level0)
{
    jsPlayer_->HandleListenerStateChange("timeUpdate", true);
    EXPECT_EQ(player_->progressReportCnt_.load(), 1);
    EXPECT_TRUE(player_->lastProgressStatus_);
    EXPECT_TRUE(jsPlayer_->reportMediaProgressCallbackflag_);
    jsPlayer_->HandleListenerStateChange("timeUpdate", false);
    EXPECT_FALSE(jsPlayer_->reportMediaProgressCallbackflag_);
}

HWTEST_F(AVPlayerNapiTest, HandleListenerStateChange_AudioInterrupt_001, TestSize.Level0)
{
    jsPlayer_->HandleListenerStateChange("audioInterrupt", true);
    EXPECT_EQ(player_->interruptReportCnt_.load(), 1);
    EXPECT_TRUE(player_->lastInterruptStatus_);
}

HWTEST_F(AVPlayerNapiTest, HandleListenerStateChange_Subtitle_001, TestSize.Level0)
{
    jsPlayer_->HandleListenerStateChange("subtitleUpdate", true);
    EXPECT_EQ(player_->subtitleDfxCnt_.load(), 1);
    EXPECT_TRUE(player_->lastSubtitleStatus_);
}

HWTEST_F(AVPlayerNapiTest, SeiMessageCallbackOn_001, TestSize.Level0)
{
    std::vector<int32_t> payloadTypes = {1, 2, 3};
    jsPlayer_->SeiMessageCallbackOn(jsPlayer_, "seiMessageReceived", payloadTypes);
    EXPECT_TRUE(jsPlayer_->seiMessageCallbackflag_);
    EXPECT_EQ(player_->seiCbCnt_.load(), 1);
    EXPECT_TRUE(player_->lastSeiStatus_);
    EXPECT_EQ(player_->lastSeiPayloadTypes_.size(), static_cast<size_t>(3));
}

HWTEST_F(AVPlayerNapiTest, SeiMessageCallbackOn_OtherEvent_001, TestSize.Level0)
{
    std::vector<int32_t> payloadTypes = {1};
    jsPlayer_->SeiMessageCallbackOn(jsPlayer_, "otherEvent", payloadTypes);
    EXPECT_FALSE(jsPlayer_->seiMessageCallbackflag_);
    EXPECT_EQ(player_->seiCbCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ResetUserParameters_001, TestSize.Level0)
{
    jsPlayer_->url_ = "http://example.com/test.mp4";
    jsPlayer_->fileDescriptor_.fd = 3;
    jsPlayer_->fileDescriptor_.offset = 100;
    jsPlayer_->fileDescriptor_.length = 500;
    jsPlayer_->width_ = 1920;
    jsPlayer_->height_ = 1080;
    jsPlayer_->position_ = 555;
    jsPlayer_->duration_ = 777;
    jsPlayer_->loop_ = true;
    jsPlayer_->mediaSourceRefList_.push_back({"srcId1", nullptr});

    jsPlayer_->ResetUserParameters();

    EXPECT_TRUE(jsPlayer_->url_.empty());
    EXPECT_EQ(jsPlayer_->fileDescriptor_.fd, 0);
    EXPECT_EQ(jsPlayer_->fileDescriptor_.offset, 0);
    EXPECT_EQ(jsPlayer_->fileDescriptor_.length, -1);
    EXPECT_EQ(jsPlayer_->width_, 0);
    EXPECT_EQ(jsPlayer_->height_, 0);
    EXPECT_EQ(jsPlayer_->position_, -1);
    EXPECT_EQ(jsPlayer_->duration_, -1);
    EXPECT_FALSE(jsPlayer_->loop_);
    EXPECT_TRUE(jsPlayer_->mediaSourceRefList_.empty());
    EXPECT_EQ(player_->resetListParamsCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, ResetUserParameters_NullPlayer_001, TestSize.Level0)
{
    jsPlayer_->url_ = "http://example.com/test.mp4";
    jsPlayer_->player_ = nullptr;
    jsPlayer_->ResetUserParameters();
    EXPECT_TRUE(jsPlayer_->url_.empty());
    jsPlayer_->player_ = player_;
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_Initialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->prepareAsyncCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_Stopped_001, TestSize.Level0)
{
    SetState(PLAYER_STOPPED);
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->prepareAsyncCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_AlreadyPrepared_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->prepareAsyncCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_NE(ret.second.find("Prepare operation only supports stopped/initialized"), std::string::npos);
    EXPECT_EQ(player_->prepareAsyncCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "failed to prepare");
    EXPECT_EQ(player_->prepareAsyncCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, PrepareTask_EnterErrorState_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    jsPlayer_->avplayerExit_ = false;
    auto task = jsPlayer_->PrepareTask();
    ASSERT_NE(task, nullptr);
    jsPlayer_->NotifyState(PLAYER_STATE_ERROR);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
}

HWTEST_F(AVPlayerNapiTest, PlayTask_Prepared_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->PlayTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->playCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, PlayTask_PausedAndCompleted_001, TestSize.Level0)
{
    SetState(PLAYER_PAUSED);
    auto task = jsPlayer_->PlayTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    SetState(PLAYER_PLAYBACK_COMPLETE);
    auto task2 = jsPlayer_->PlayTask();
    auto ret2 = GetTaskResultValue(task2);
    EXPECT_EQ(ret2.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->playCnt_.load(), 2);
}

HWTEST_F(AVPlayerNapiTest, PlayTask_AlreadyPlaying_001, TestSize.Level0)
{
    SetState(PLAYER_STARTED);
    auto task = jsPlayer_->PlayTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->playCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PlayTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->PlayTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->playCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PauseTask_Playing_001, TestSize.Level0)
{
    SetState(PLAYER_STARTED);
    auto task = jsPlayer_->PauseTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->pauseCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, PauseTask_AlreadyPaused_001, TestSize.Level0)
{
    SetState(PLAYER_PAUSED);
    auto task = jsPlayer_->PauseTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->pauseCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PauseTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->PauseTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_NE(ret.second.find("Pause operation only supports playing"), std::string::npos);
    EXPECT_EQ(player_->pauseCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, PauseTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_STARTED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->PauseTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "failed to Pause");
}

HWTEST_F(AVPlayerNapiTest, StopTask_Controllable_001, TestSize.Level0)
{
    SetState(PLAYER_PAUSED);
    auto task = jsPlayer_->StopTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->stopCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, StopTask_AlreadyStopped_001, TestSize.Level0)
{
    SetState(PLAYER_STOPPED);
    auto task = jsPlayer_->StopTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->stopCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, StopTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->StopTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_NE(ret.second.find("Stop operation only supports prepared/playing/paused/completed"), std::string::npos);
    EXPECT_EQ(player_->stopCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ResetTask_NotIdle_001, TestSize.Level0)
{
    SetState(PLAYER_PAUSED);
    auto task = jsPlayer_->ResetTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->resetCnt_.load(), 1);
    EXPECT_EQ(player_->resetListParamsCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, ResetTask_Idle_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->ResetTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->resetCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ResetTask_Released_001, TestSize.Level0)
{
    jsPlayer_->isReleased_.store(true);
    auto task = jsPlayer_->ResetTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_NE(ret.second.find("unsupport reset operation"), std::string::npos);
    EXPECT_EQ(player_->resetCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ResetTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->ResetTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "failed to Reset");
}

HWTEST_F(AVPlayerNapiTest, ReleaseTask_001, TestSize.Level0)
{
    auto task = jsPlayer_->ReleaseTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->releaseSyncCnt_.load(), 1);
    EXPECT_TRUE(jsPlayer_->isReleased_.load());
    EXPECT_EQ(jsPlayer_->GetCurrentState(), AVPlayerState::STATE_RELEASED);
    jsPlayer_->WaitTaskQueStop();
}

HWTEST_F(AVPlayerNapiTest, ReleaseTask_Twice_ReturnsNull_001, TestSize.Level0)
{
    auto task = jsPlayer_->ReleaseTask();
    ASSERT_NE(task, nullptr);
    (void)GetTaskResultValue(task);
    auto task2 = jsPlayer_->ReleaseTask();
    EXPECT_EQ(task2, nullptr);
    jsPlayer_->WaitTaskQueStop();
}

HWTEST_F(AVPlayerNapiTest, EqueueSetPlayRangeTask_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->EqueueSetPlayRangeTask(100, 5000, 2);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setPlayRangeCnt_.load(), 1);
    EXPECT_EQ(player_->lastRangeStart_, 100);
    EXPECT_EQ(player_->lastRangeEnd_, 5000);
    EXPECT_EQ(player_->lastRangeMode_, PlayerSeekMode::SEEK_CLOSEST);
}

HWTEST_F(AVPlayerNapiTest, EqueueSetPlayRangeTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->EqueueSetPlayRangeTask(100, 5000, 1);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "failed to setPlaybackRange");
    EXPECT_EQ(player_->setPlayRangeCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, EqueueSetPlayRangeTask_NullPlayer_001, TestSize.Level0)
{
    jsPlayer_->player_ = nullptr;
    auto task = jsPlayer_->EqueueSetPlayRangeTask(100, 5000, 1);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    jsPlayer_->player_ = player_;
}

HWTEST_F(AVPlayerNapiTest, SetMediaMutedTask_Initialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    auto task = jsPlayer_->SetMediaMutedTask(MediaType::MEDIA_TYPE_AUD, true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setMediaMutedCnt_.load(), 1);
    EXPECT_EQ(player_->lastMutedType_, MediaType::MEDIA_TYPE_AUD);
    EXPECT_TRUE(player_->lastMuted_);
}

HWTEST_F(AVPlayerNapiTest, SetMediaMutedTask_Controllable_001, TestSize.Level0)
{
    SetState(PLAYER_PAUSED);
    auto task = jsPlayer_->SetMediaMutedTask(MediaType::MEDIA_TYPE_AUD, false);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setMediaMutedCnt_.load(), 1);
    EXPECT_FALSE(player_->lastMuted_);
}

HWTEST_F(AVPlayerNapiTest, SetMediaMutedTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->SetMediaMutedTask(MediaType::MEDIA_TYPE_AUD, true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->setMediaMutedCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetMediaMutedTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->SetMediaMutedTask(MediaType::MEDIA_TYPE_VID, true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "failed to set muted");
}

HWTEST_F(AVPlayerNapiTest, SetPlaybackStrategyTask_Initialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    AVPlayStrategy strategy {};
    strategy.preferredWidth = 1920;
    strategy.preferredHeight = 1080;
    auto task = jsPlayer_->SetPlaybackStrategyTask(strategy);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setPlaybackStrategyCnt_.load(), 1);
    EXPECT_EQ(player_->lastStrategy_.preferredWidth, 1920u);
}

HWTEST_F(AVPlayerNapiTest, SetPlaybackStrategyTask_Stopped_001, TestSize.Level0)
{
    SetState(PLAYER_STOPPED);
    AVPlayStrategy strategy {};
    auto task = jsPlayer_->SetPlaybackStrategyTask(strategy);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setPlaybackStrategyCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, SetPlaybackStrategyTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    AVPlayStrategy strategy {};
    auto task = jsPlayer_->SetPlaybackStrategyTask(strategy);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->setPlaybackStrategyCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetTrackSelectionFilterTask_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    AVPlayTrackSelectionFilter filter {};
    filter.maxVideoBitrate = 5000;
    auto task = jsPlayer_->SetTrackSelectionFilterTask(filter);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setTrackFilterCnt_.load(), 1);
    EXPECT_EQ(player_->lastFilter_.maxVideoBitrate, 5000);
}

HWTEST_F(AVPlayerNapiTest, SetTrackSelectionFilterTask_Released_001, TestSize.Level0)
{
    jsPlayer_->isReleased_.store(true);
    AVPlayTrackSelectionFilter filter {};
    auto task = jsPlayer_->SetTrackSelectionFilterTask(filter);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->setTrackFilterCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSuperResolutionTask_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->SetSuperResolutionTask(true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setSuperResCnt_.load(), 1);
    EXPECT_TRUE(player_->lastSuperRes_);
}

HWTEST_F(AVPlayerNapiTest, SetSuperResolutionTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto task = jsPlayer_->SetSuperResolutionTask(true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->setSuperResCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetVideoWindowSizeTask_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->SetVideoWindowSizeTask(1280, 720);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->setVideoWinCnt_.load(), 1);
    EXPECT_EQ(player_->lastWinWidth_, 1280);
    EXPECT_EQ(player_->lastWinHeight_, 720);
}

HWTEST_F(AVPlayerNapiTest, SetVideoWindowSizeTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_STATE_ERROR);
    auto task = jsPlayer_->SetVideoWindowSizeTask(1280, 720);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->setVideoWinCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, EnableCameraPostprocessingTask_Initialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    auto task = jsPlayer_->EnableCameraPostprocessingTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->cameraPostCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, EnableCameraPostprocessingTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->EnableCameraPostprocessingTask();
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->cameraPostCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ForceLoadVideoTask_Initialized_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    auto task = jsPlayer_->ForceLoadVideoTask(true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->forceLoadCnt_.load(), 1);
    EXPECT_TRUE(player_->lastForceLoad_);
}

HWTEST_F(AVPlayerNapiTest, ForceLoadVideoTask_Stopped_001, TestSize.Level0)
{
    SetState(PLAYER_STOPPED);
    auto task = jsPlayer_->ForceLoadVideoTask(false);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(player_->forceLoadCnt_.load(), 1);
    EXPECT_FALSE(player_->lastForceLoad_);
}

HWTEST_F(AVPlayerNapiTest, ForceLoadVideoTask_InvalidState_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto task = jsPlayer_->ForceLoadVideoTask(true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_EQ(player_->forceLoadCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, ForceLoadVideoTask_PlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->ForceLoadVideoTask(true);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_NE(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(ret.second, "ForceLoadVideo failed");
}

HWTEST_F(AVPlayerNapiTest, GetTrackDescriptionTask_Controllable_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    auto promiseCtx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    auto task = jsPlayer_->GetTrackDescriptionTask(promiseCtx);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(promiseCtx->trackInfoVec_.size(), static_cast<size_t>(3));
}

HWTEST_F(AVPlayerNapiTest, GetTrackDescriptionTask_Uncontrollable_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    auto promiseCtx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    auto task = jsPlayer_->GetTrackDescriptionTask(promiseCtx);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
    EXPECT_TRUE(promiseCtx->trackInfoVec_.empty());
}

HWTEST_F(AVPlayerNapiTest, GetTrackSelectionFilterTask_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    player_->lastFilter_.maxVideoBitrate = 6000;
    auto promiseCtx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    auto task = jsPlayer_->GetTrackSelectionFilterTask(promiseCtx);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OK);
    EXPECT_EQ(promiseCtx->trackFilter_.maxVideoBitrate, 6000);
}

HWTEST_F(AVPlayerNapiTest, GetTrackSelectionFilterTask_Released_001, TestSize.Level0)
{
    jsPlayer_->isReleased_.store(true);
    auto promiseCtx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    auto task = jsPlayer_->GetTrackSelectionFilterTask(promiseCtx);
    ASSERT_NE(task, nullptr);
    auto ret = GetTaskResultValue(task);
    EXPECT_EQ(ret.first, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
}

HWTEST_F(AVPlayerNapiTest, SetSource_Network_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("http://example.com/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 1);
    EXPECT_EQ(player_->lastUrl_, "http://example.com/test.mp4");
}

HWTEST_F(AVPlayerNapiTest, SetSource_Https_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("https://example.com/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, SetSource_Fd_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("fd://123");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceFdCnt_.load(), 1);
    EXPECT_EQ(player_->lastFd_, 123);
}

HWTEST_F(AVPlayerNapiTest, SetSource_FdInvalid_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("fd://abc");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceFdCnt_.load(), 0);
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSource_FdNegative_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("fd://-1");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceFdCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSource_UnsupportedScheme_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    jsPlayer_->SetSource("/data/local/tmp/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceFdCnt_.load(), 0);
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSource_NetworkNotIdle_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    jsPlayer_->SetSource("http://example.com/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSource_FdNotIdle_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    jsPlayer_->SetSource("fd://123");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceFdCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, SetSource_NetworkPlayerError_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    player_->SetResult(MSERR_INVALID_OPERATION);
    jsPlayer_->SetSource("http://example.com/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, SetSource_CleartextNotPermitted_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    player_->SetResult(MSERR_CLEARTEXT_NOT_PERMITTED);
    jsPlayer_->SetSource("http://example.com/test.mp4");
    SyncTaskQueue();
    EXPECT_EQ(player_->setSourceUrlCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, DoSeek_LiveOutOfRange_001, TestSize.Level0)
{
    jsPlayer_->NotifyIsLiveStream();
    player_->SetSeekableRangeMs(0, 20);
    AVPlayerNapi::DoSeek(jsPlayer_, 100, 1);
    EXPECT_EQ(player_->seekCnt_.load(), 0);
}

HWTEST_F(AVPlayerNapiTest, AvPlayerContext_DefaultFields_001, TestSize.Level0)
{
    auto ctx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->asyncTask, nullptr);
    EXPECT_EQ(ctx->napi, nullptr);
    EXPECT_EQ(ctx->commandValue, -1);
    EXPECT_TRUE(ctx->trackInfoVec_.empty());
    EXPECT_EQ(ctx->listOp, AVPlayerNapi::AVPlayerContext::ListOp::NONE);
    EXPECT_TRUE(ctx->srcId.empty());
    EXPECT_TRUE(ctx->generateSrcId.empty());
}

HWTEST_F(AVPlayerNapiTest, AvPlayerContext_CheckTaskResult_NullTask_001, TestSize.Level0)
{
    auto ctx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    ctx->CheckTaskResult();
    EXPECT_FALSE(ctx->errFlag);
    EXPECT_EQ(ctx->errCode, 0);
}

HWTEST_F(AVPlayerNapiTest, AvPlayerContext_CheckTaskResult_OkTask_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    auto task = jsPlayer_->PrepareTask();
    auto ctx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    ctx->asyncTask = task;
    ctx->CheckTaskResult(true, 100);
    EXPECT_FALSE(ctx->errFlag);
}

HWTEST_F(AVPlayerNapiTest, AvPlayerContext_CheckTaskResult_ErrorTask_001, TestSize.Level0)
{
    SetState(PLAYER_INITIALIZED);
    player_->SetResult(MSERR_INVALID_OPERATION);
    auto task = jsPlayer_->PrepareTask();
    auto ctx = std::make_unique<AVPlayerNapi::AVPlayerContext>(nullptr);
    ctx->asyncTask = task;
    ctx->CheckTaskResult();
    EXPECT_TRUE(ctx->errFlag);
    EXPECT_NE(ctx->errCode, MSERR_EXT_API9_OK);
    EXPECT_EQ(ctx->errMessage, "failed to prepare");
}

HWTEST_F(AVPlayerNapiTest, GetJsApiVersion_001, TestSize.Level0)
{
    player_->SetApiVersionValue(4242);
    jsPlayer_->getApiVersionFlag_ = true;
    int32_t version = jsPlayer_->GetJsApiVersion();
    EXPECT_EQ(version, 4242);
    EXPECT_EQ(player_->apiVersionCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, GetJsApiVersion_OnlyQueryOnce_001, TestSize.Level0)
{
    player_->SetApiVersionValue(4343);
    jsPlayer_->getApiVersionFlag_ = true;
    (void)jsPlayer_->GetJsApiVersion();
    int32_t version = jsPlayer_->GetJsApiVersion();
    EXPECT_EQ(version, 4343);
    EXPECT_EQ(player_->apiVersionCnt_.load(), 1);
}

HWTEST_F(AVPlayerNapiTest, GetJsApiVersion_NullPlayer_001, TestSize.Level0)
{
    jsPlayer_->player_ = nullptr;
    jsPlayer_->getApiVersionFlag_ = true;
    (void)jsPlayer_->GetJsApiVersion();
    EXPECT_EQ(player_->apiVersionCnt_.load(), 0);
    jsPlayer_->player_ = player_;
}

HWTEST_F(AVPlayerNapiTest, IsListMode_Empty_001, TestSize.Level0)
{
    EXPECT_FALSE(AVPlayerNapi::IsListMode(jsPlayer_));
}

HWTEST_F(AVPlayerNapiTest, IsListMode_WithMediaSource_001, TestSize.Level0)
{
    jsPlayer_->mediaSourceRefList_.push_back({"srcId1", nullptr});
    EXPECT_TRUE(AVPlayerNapi::IsListMode(jsPlayer_));
}

HWTEST_F(AVPlayerNapiTest, IsListMode_NullJsPlayer_001, TestSize.Level0)
{
    EXPECT_FALSE(AVPlayerNapi::IsListMode(nullptr));
}

HWTEST_F(AVPlayerNapiTest, IsAllowAdvanceToMediaSource_AllowedStates_001, TestSize.Level0)
{
    SetState(PLAYER_PREPARED);
    EXPECT_TRUE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_STARTED);
    EXPECT_TRUE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_PAUSED);
    EXPECT_TRUE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_PLAYBACK_COMPLETE);
    EXPECT_TRUE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_STATE_ERROR);
    EXPECT_TRUE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
}

HWTEST_F(AVPlayerNapiTest, IsAllowAdvanceToMediaSource_DeniedStates_001, TestSize.Level0)
{
    SetState(PLAYER_IDLE);
    EXPECT_FALSE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_INITIALIZED);
    EXPECT_FALSE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
    SetState(PLAYER_STOPPED);
    EXPECT_FALSE(AVPlayerNapi::IsAllowAdvanceToMediaSource(jsPlayer_));
}

HWTEST_F(AVPlayerNapiTest, IsLiveSource_DefaultFalse_001, TestSize.Level0)
{
    EXPECT_FALSE(jsPlayer_->IsLiveSource());
}

HWTEST_F(AVPlayerNapiTest, GetPlayerInstance_001, TestSize.Level0)
{
    EXPECT_EQ(jsPlayer_->GetPlayerInstance(), player_);
}
} // namespace Media
} // namespace OHOS
