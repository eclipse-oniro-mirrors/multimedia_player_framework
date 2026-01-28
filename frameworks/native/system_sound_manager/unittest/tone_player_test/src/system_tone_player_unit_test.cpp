/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "system_tone_player_unit_test.h"
#include "system_tone_player_impl.h"

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void SystemTonePlayerUnitTest::SetUpTestCase(void) {}
void SystemTonePlayerUnitTest::TearDownTestCase(void) {}
void SystemTonePlayerUnitTest::SetUp(void) {}
void SystemTonePlayerUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: InitPlayer_001
 * @tc.desc  : Test InitPlayer interface.
 */
HWTEST(SystemTonePlayerUnitTest, InitPlayer_001, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);

    std::string audioUri = NO_SYSTEM_SOUND;
    int32_t temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: InitPlayer_002
 * @tc.desc  : Test InitPlayer interface.
 */
HWTEST(SystemTonePlayerUnitTest, InitPlayer_002, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);

    std::string audioUri = NO_RING_SOUND;
    int32_t temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_001
 * @tc.desc  : Test CreatePlayerWithOptions. Returns MSERR_OK.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_001, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    AudioHapticPlayerOptions options = { false, false};
    int32_t result = systemTonePlayerImpl_->CreatePlayerWithOptions(options);
    EXPECT_NE(result, -1);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_002
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_002, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/ringtone.ogg";
    std::string ringtonePath = "/data/test/";
    std::string hapticsPath = "/data/test/";
    std::string result = systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "/data/test/ringtone.json");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_003
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_003, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/media/audio/test.oggg";
    std::string ringtonePath = "/media/audio/";
    std::string hapticsPath = "/media/haptics/";
    std::string result = systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_004
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_004, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = ".ogg";
    std::string ringtonePath = ".";
    std::string hapticsPath = ".";
    std::string result = systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_005
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_005, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/";
    std::string ringtonePath = "/";
    std::string hapticsPath = "/";
    std::string result = systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_007
 * @tc.desc  : Test GetHapticUriForAudioUri. Returns void
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_007, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = ".og";
    std::map<ToneHapticsFeature, std::string> hapticsUriMap;
    hapticsUriMap[ToneHapticsFeature::STANDARD] = "test1";
    hapticsUriMap[ToneHapticsFeature::GENTLE] = "test2";
    systemTonePlayerImpl_->GetHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::STANDARD], " ");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], " ");
    audioUri = ".ogg";
    systemTonePlayerImpl_->GetHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::STANDARD], " ");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], " ");
    audioUri = "audio.oggg";
    systemTonePlayerImpl_->GetHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::STANDARD], " ");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], " ");
    audioUri = "/data/test/ringtone.ogg";
    systemTonePlayerImpl_->GetHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_EQ(hapticsUriMap[ToneHapticsFeature::STANDARD], "/data/test/ringtone.json");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], " ");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_010
 * @tc.desc  : Test Prepare. Returns MSERR_OK
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_010, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    int32_t temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
    int32_t result = systemTonePlayerImpl_->Prepare();
    EXPECT_EQ(result, MSERR_OK);
    audioUri = "";
    temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
    result = systemTonePlayerImpl_->Prepare();
    EXPECT_NE(result, MSERR_INVALID_STATE);
    std::string systemToneUri = systemSoundMgr_->GetSystemToneUri(context_, systemToneType);
    temp = systemTonePlayerImpl_->InitPlayer(systemToneUri);
    EXPECT_EQ(temp, MSERR_OK);
    result = systemTonePlayerImpl_->Prepare();
    EXPECT_EQ(result, MSERR_OK);
    systemTonePlayerImpl_.reset();
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_011
 * @tc.desc  : Test Release. Returns MSERR_OK
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_011, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t result = systemTonePlayerImpl_->Release();
    EXPECT_EQ(result, MSERR_OK);
    result = systemTonePlayerImpl_->Release();
    EXPECT_EQ(result, MSERR_OK);
    systemTonePlayerImpl_.reset();
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_012
 * @tc.desc  : Test DeletePlayer.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_012, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t streamId = 0;
    systemTonePlayerImpl_->DeletePlayer(streamId);
    EXPECT_EQ(streamId, 0);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_013
 * @tc.desc  : Test OnInterrupt.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_013, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t streamId = 0;
    auto systemTonePlayerCallback_ = std::make_shared<SystemTonePlayerCallback>(streamId, systemTonePlayerImpl_);
    OHOS::AudioStandard::InterruptEvent interruptEvent;
    systemTonePlayerCallback_->OnInterrupt(interruptEvent);
    EXPECT_NE(systemTonePlayerCallback_, nullptr);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_014
 * @tc.desc  : Test OnEndOfStream.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_014, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t streamId = 0;
    auto systemTonePlayerCallback_ = std::make_shared<SystemTonePlayerCallback>(streamId, systemTonePlayerImpl_);
    systemTonePlayerCallback_->OnEndOfStream();
    EXPECT_NE(systemTonePlayerCallback_, nullptr);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_015
 * @tc.desc  : Test SetAudioVolume. Return MSERR_OK
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_015, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    int32_t temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
    float volume = -1;
    int32_t result = systemTonePlayerImpl_->SetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
    volume = 2;
    result = systemTonePlayerImpl_->SetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
    volume = 0.5;
    result = systemTonePlayerImpl_->SetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_016
 * @tc.desc  : Test ConvertToToneHapticsType. Return ToneHapticsType
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_016, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    ToneHapticsType result = systemTonePlayerImpl_->ConvertToToneHapticsType(
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result, ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_EQ(result, ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result, ToneHapticsType::NOTIFICATION);
    SystemToneType temp = static_cast<SystemToneType>(99);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(temp);
    EXPECT_EQ(result, ToneHapticsType::NOTIFICATION);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_017
 * @tc.desc  : Test ConvertToHapticsMode. Return HapticsMode
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_017, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    HapticsMode result = systemTonePlayerImpl_->ConvertToHapticsMode(ToneHapticsMode::NONE);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_NONE);
    result = systemTonePlayerImpl_->ConvertToHapticsMode(ToneHapticsMode::SYNC);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_SYNC);
    result = systemTonePlayerImpl_->ConvertToHapticsMode(ToneHapticsMode::NON_SYNC);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE);
    ToneHapticsMode temp = static_cast<ToneHapticsMode>(99);
    result = systemTonePlayerImpl_->ConvertToHapticsMode(temp);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_INVALID);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_018
 * @tc.desc  : Test GetNewHapticSettings.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_018, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::map<ToneHapticsFeature, std::string> hapticsUris;
    systemTonePlayerImpl_->GetNewHapticSettings("", hapticsUris);
    EXPECT_EQ(hapticsUris.empty(), true);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_019
 * @tc.desc  : Test InitHapticsSourceIds.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_019, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    systemTonePlayerImpl_->InitHapticsSourceIds();
    EXPECT_EQ(audioUri, "/storage/media/local/files/test.ogg");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_022
 * @tc.desc  : Test Start. Return streamId
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_022, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t result = 0;
    std::string audioUri = "/data/test/ringtone.ogg";
    for (int i = 0; i < 129; i++) {
        systemTonePlayerImpl_->InitHapticsSourceIds();
        result += systemTonePlayerImpl_->Start();
    }
    EXPECT_NE(result, 0);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_023
 * @tc.desc  : Test Start. Return streamId
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_023, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = systemTonePlayerImpl_->configuredUri_;
    SystemToneOptions options = {false, false};
    systemTonePlayerImpl_->InitPlayer(audioUri);
    systemSoundMgr_->SetRingerMode(AudioStandard::AudioRingerMode::RINGER_MODE_SILENT);
    int32_t result = systemTonePlayerImpl_->Start(options);
    EXPECT_NE(result, 0);
    systemTonePlayerImpl_->Release();
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_024
 * @tc.desc  : Test Stop And DeleteAllPlayer.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_024, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/ringtone.ogg";
    int32_t result = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(result, MSERR_OK);
    systemTonePlayerImpl_->InitHapticsSourceIds();
    int32_t streamId = systemTonePlayerImpl_->Start();
    result = systemTonePlayerImpl_->Stop(streamId);
    EXPECT_EQ(result, MSERR_OK);
    result = systemTonePlayerImpl_->Release();
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_025
 * @tc.desc  : Test ReleaseHapticsSourceIds.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_025, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/ringtone.ogg";
    systemTonePlayerImpl_->InitHapticsSourceIds();
    systemTonePlayerImpl_->ReleaseHapticsSourceIds();
    EXPECT_NE(systemTonePlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_026
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns void.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_026, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/media/audio/ringtone.ogg";
    std::map<ToneHapticsFeature, std::string> hapticsUriMap;
    hapticsUriMap[ToneHapticsFeature::STANDARD] = "test1";
    hapticsUriMap[ToneHapticsFeature::GENTLE] = "test2";
    systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::STANDARD], "");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], "");
    audioUri = "/data/test/ringtone.ogg";
    systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::STANDARD], "");
    EXPECT_NE(hapticsUriMap[ToneHapticsFeature::GENTLE], "");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_027
 * @tc.desc  : Test InitHapticsSourceIds.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_027, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_1;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/media/audio/ringtone.ogg";
    systemTonePlayerImpl_->InitHapticsSourceIds();
    EXPECT_EQ(audioUri, "/data/test/media/audio/ringtone.ogg");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_028
 * @tc.desc  : Test SetAudioVolume. Return MSERR_OK
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_028, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    int32_t temp = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(temp, MSERR_OK);
    float volume = 1.000001;
    int32_t result = systemTonePlayerImpl_->SetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
    volume = -0.000001;
    result = systemTonePlayerImpl_->SetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_029
 * @tc.desc  : Test GetTitle. Return title
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_029, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    systemTonePlayerImpl_->GetTitle();
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_030
 * @tc.desc  : Test GetAudioVolume. Return volume
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_030, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    float volume;
    int32_t result = systemTonePlayerImpl_->GetAudioVolume(volume);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_031
 * @tc.desc  : Test SetHapticsFeature And GetHapticsFeature. Return MSERR_OK
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_031, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/ringtone.ogg";
    int32_t result = systemTonePlayerImpl_->InitPlayer(audioUri);
    EXPECT_EQ(result, MSERR_OK);
    systemTonePlayerImpl_->InitHapticsSourceIds();
    result = systemTonePlayerImpl_->SetHapticsFeature(ToneHapticsFeature::STANDARD);
    EXPECT_EQ(result, MSERR_OK);
    ToneHapticsFeature feature;
    result = systemTonePlayerImpl_->GetHapticsFeature(feature);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_032
 * @tc.desc  : Test GetDefaultNonSyncHapticsPath
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_032, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string result = systemTonePlayerImpl_->GetDefaultNonSyncHapticsPath();
    EXPECT_NE(result, " ");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_033
 * @tc.desc  : Test UpdateStreamId
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_033, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    systemTonePlayerImpl_->UpdateStreamId();
    EXPECT_NE(systemTonePlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_034
 * @tc.desc  : Test Stop
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_034, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    int32_t result = systemTonePlayerImpl_->Stop(0);
    EXPECT_NE(result, 1);
    AudioHapticPlayerOptions options = { false, false};
    systemTonePlayerImpl_->playerMap_[0] = systemTonePlayerImpl_->audioHapticManager_->CreatePlayer(
        systemTonePlayerImpl_->sourceIds_[ToneHapticsFeature::STANDARD], options);
    systemTonePlayerImpl_->playerMap_[1] = systemTonePlayerImpl_->audioHapticManager_->CreatePlayer(
        systemTonePlayerImpl_->sourceIds_[ToneHapticsFeature::STANDARD], options);
    systemTonePlayerImpl_->systemToneState_ = SystemToneState::STATE_RUNNING;
    result = systemTonePlayerImpl_->Stop(0);
    EXPECT_NE(result, 1);
    result = systemTonePlayerImpl_->Stop(1);
    EXPECT_NE(result, 1);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_035
 * @tc.desc  : Test DeletePlayer
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_035, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    AudioHapticPlayerOptions options = { false, false};
    systemTonePlayerImpl_->playerMap_[0] = systemTonePlayerImpl_->audioHapticManager_->CreatePlayer(
        systemTonePlayerImpl_->sourceIds_[ToneHapticsFeature::STANDARD], options);
    systemTonePlayerImpl_->playerMap_[1] = systemTonePlayerImpl_->audioHapticManager_->CreatePlayer(
        systemTonePlayerImpl_->sourceIds_[ToneHapticsFeature::STANDARD], options);
    systemTonePlayerImpl_->playerMap_[2] = nullptr;
    systemTonePlayerImpl_->systemToneState_ = SystemToneState::STATE_RUNNING;
    systemTonePlayerImpl_->DeletePlayer(0);
    systemTonePlayerImpl_->DeletePlayer(1);
    systemTonePlayerImpl_->DeletePlayer(2);
    EXPECT_NE(systemTonePlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_RegisterSource_001
 * @tc.desc  : Test DeletePlayer.
 */
HWTEST(SystemTonePlayerUnitTest, RegisterSource_001, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/data/test/ringtone.ogg";
    std::string hapticUri = "/data/test/ringtone.json";
    int32_t res = systemTonePlayerImpl_->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(res, 0);
    audioUri = "no_system_sound";
    res = systemTonePlayerImpl_->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(res, 0);
}
} // namespace Media
} // namespace OHOS
