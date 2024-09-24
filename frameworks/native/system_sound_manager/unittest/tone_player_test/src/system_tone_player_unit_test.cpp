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
    EXPECT_NO_THROW(
        systemTonePlayerImpl_->CreatePlayerWithOptions(options);
    );
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
    std::string audioUri = "/media/audio/test.ogg";
    std::string ringtonePath = "/media/audio/";
    std::string hapticsPath = "/media/haptics/";
    std::string result = systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
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
 * @tc.number: Media_TonePlayert_006
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns void.
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_006, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/media/audio/test.ogg";
    std::map<ToneHapticsFeature, std::string> hapticsUriMap;
    hapticsUriMap[ToneHapticsFeature::STANDARD] = "test1";
    hapticsUriMap[ToneHapticsFeature::GENTLE] = "test2";
    systemTonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, hapticsUriMap);
    EXPECT_EQ(hapticsUriMap[ToneHapticsFeature::STANDARD], "test1");
    EXPECT_EQ(hapticsUriMap[ToneHapticsFeature::GENTLE], "test2");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_008
 * @tc.desc  : Test ChangeUri. Returns Uri
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_008, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    std::string result = systemTonePlayerImpl_->ChangeUri(audioUri);
    EXPECT_EQ(result, "/storage/media/local/files/test.ogg");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_009
 * @tc.desc  : Test ChangeUri. Returns Uri
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_009, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string audioUri = "/storage/media/local/test.ogg";
    std::string result = systemTonePlayerImpl_->ChangeUri(audioUri);
    EXPECT_EQ(result, "/storage/media/local/test.ogg");
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
 * @tc.desc  : Test OnInterrupt.
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
    EXPECT_EQ(result, ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_0);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_EQ(result, ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_1);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result, ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION);
    SystemToneType temp = static_cast<SystemToneType>(99);
    result = systemTonePlayerImpl_->ConvertToToneHapticsType(temp);
    EXPECT_EQ(result, ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION);
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
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_NON_SYNC);
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
    hapticsUris[ToneHapticsFeature::STANDARD] = "test1";
    hapticsUris[ToneHapticsFeature::GENTLE] = "test2";
    systemTonePlayerImpl_->GetNewHapticSettings(hapticsUris);
    EXPECT_EQ(hapticsUris[ToneHapticsFeature::STANDARD], "test1");
    EXPECT_EQ(hapticsUris[ToneHapticsFeature::GENTLE], "test2");
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
    systemTonePlayerImpl_->InitHapticsSourceIds(audioUri);
    EXPECT_EQ(audioUri, "/storage/media/local/files/test.ogg");
}

/**
 * @tc.name  : Test MediaTonePlayer
 * @tc.number: Media_TonePlayert_021
 * @tc.desc  : Test ChangeHapticsUri. Returns HapticsUri
 */
HWTEST(SystemTonePlayerUnitTest, Media_TonePlayer_Unit_Test_021, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto systemSoundMgr_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    auto systemTonePlayerImpl_ = std::make_shared<SystemTonePlayerImpl>(context_, *systemSoundMgr_, systemToneType);
    std::string hapticsUri = "/storage/media/local/test.ogg";
    std::string result = systemTonePlayerImpl_->ChangeHapticsUri(hapticsUri);
    EXPECT_EQ(result, "/storage/media/local/test.ogg");
}
} // namespace Media
} // namespace OHOS
