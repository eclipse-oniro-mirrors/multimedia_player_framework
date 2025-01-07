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
#include "ringtone_player_unit_test.h"
#include "ringtone_player_impl.h"

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void RingtonePlayerUnitTest::SetUpTestCase(void) {}
void RingtonePlayerUnitTest::TearDownTestCase(void) {}
void RingtonePlayerUnitTest::SetUp(void) {}
void RingtonePlayerUnitTest::TearDown(void) {}


/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_001
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_001, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/data/test/ringtone.ogg";
    std::string ringtonePath = "/data/test/";
    std::string hapticsPath = "/data/test/";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "/data/test/ringtone.json");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_002
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_002, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/media/audio/test.oggg";
    std::string ringtonePath = "/media/audio/";
    std::string hapticsPath = "/media/haptics/";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_003
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_003, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = ".ogg";
    std::string ringtonePath = ".";
    std::string hapticsPath = ".";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_004
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_004, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/";
    std::string ringtonePath = "/";
    std::string hapticsPath = "/";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri, ringtonePath, hapticsPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_005
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_005, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/media/audio/test.ogg";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_006
 * @tc.desc  : Test GetNewHapticUriForAudioUri. Returns NewHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_006, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/data/test/media/audio/ringtone.ogg";
    std::string result = ringtonePlayerImpl_->GetNewHapticUriForAudioUri(audioUri);
    EXPECT_EQ(result, "/data/test/media/haptics/standard/synchronized/ringtone.json");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_007
 * @tc.desc  : Test GetHapticUriForAudioUri. Returns HapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_007, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/data/test/ringtone.ogg";
    std::string result = ringtonePlayerImpl_->GetHapticUriForAudioUri(audioUri);
    EXPECT_EQ(result, "/data/test/ringtone.json");

    audioUri = "/data/test/media/audio/ringtone.oggg";
    result = ringtonePlayerImpl_->GetHapticUriForAudioUri(audioUri);
    EXPECT_NE(result, " ");

    audioUri = "/media/audio/test.ogg";
    result = ringtonePlayerImpl_->GetHapticUriForAudioUri(audioUri);
    EXPECT_EQ(result, "/media/audio/test.json");

    audioUri = ".ogg";
    result = ringtonePlayerImpl_->GetHapticUriForAudioUri(audioUri);
    EXPECT_NE(result, " ");

    audioUri = "ogg";
    result = ringtonePlayerImpl_->GetHapticUriForAudioUri(audioUri);
    EXPECT_NE(result, " ");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_008
 * @tc.desc  : Test ChangeUri. Returns ringtoneUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_008, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string audioUri = "/storage/media/local/files/test.ogg";
    std::string result = ringtonePlayerImpl_->ChangeUri(audioUri);
    EXPECT_EQ(result, "/storage/media/local/files/test.ogg");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_009
 * @tc.desc  : Test ChangeHapticsUri. Returns newHapticsUri.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_009, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    std::string hapticsUri = "/storage/media/local/test.json";
    std::string result = ringtonePlayerImpl_->ChangeHapticsUri(hapticsUri);
    EXPECT_EQ(result, "/storage/media/local/test.json");
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_010
 * @tc.desc  : Test ConvertToToneHapticsType. Returns ToneHapticsType.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_010, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    ToneHapticsType result = ringtonePlayerImpl_->ConvertToToneHapticsType(type);
    EXPECT_EQ(result, ToneHapticsType::CALL_SIM_CARD_0);

    type = RINGTONE_TYPE_SIM_CARD_1;
    result = ringtonePlayerImpl_->ConvertToToneHapticsType(type);
    EXPECT_EQ(result, ToneHapticsType::CALL_SIM_CARD_1);

    type = static_cast<RingtoneType>(99);
    result = ringtonePlayerImpl_->ConvertToToneHapticsType(type);
    EXPECT_EQ(result, ToneHapticsType::CALL_SIM_CARD_0);
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_011
 * @tc.desc  : Test ConvertToHapticsMode. Returns ToneHapticsType.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_011, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    ToneHapticsMode toneHapticsMode = ToneHapticsMode::NONE;
    HapticsMode result = ringtonePlayerImpl_->ConvertToHapticsMode(toneHapticsMode);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_NONE);

    toneHapticsMode = ToneHapticsMode::SYNC;
    result = ringtonePlayerImpl_->ConvertToHapticsMode(toneHapticsMode);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_SYNC);

    toneHapticsMode = ToneHapticsMode::NON_SYNC;
    result = ringtonePlayerImpl_->ConvertToHapticsMode(toneHapticsMode);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_NON_SYNC);

    toneHapticsMode = static_cast<ToneHapticsMode>(99);
    result = ringtonePlayerImpl_->ConvertToHapticsMode(toneHapticsMode);
    EXPECT_EQ(result, HapticsMode::HAPTICS_MODE_INVALID);
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_012
 * @tc.desc  : Test GetHapticSettings. Returns NewHapticcsSettings.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_012, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    bool muteHaptics;
    string audioUri = "/data/test/ringtone.ogg";
    ToneHapticsSettings result = ringtonePlayerImpl_->GetHapticSettings(audioUri, muteHaptics);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_013
 * @tc.desc  : Test InitPlayer.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_013, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    ringtonePlayerImpl_->sourceId_ = -1;
    std::string audioUri = "/data/test/test.ogg";
    AudioHapticPlayerOptions options = {false, false};
    ToneHapticsSettings settings = ringtonePlayerImpl_->GetHapticSettings(audioUri, options.muteHaptics);
    sysSoundMgr->SetRingerMode(AudioStandard::AudioRingerMode::RINGER_MODE_SILENT);
    ringtonePlayerImpl_->InitPlayer(audioUri, settings, options);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);

    ringtonePlayerImpl_->sourceId_ = 1;
    audioUri = "/data/test/ringtone.ogg";
    sysSoundMgr->SetRingerMode(AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL);
    ringtonePlayerImpl_->InitPlayer(audioUri, settings, options);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);

    ringtonePlayerImpl_->sourceId_ = 1;
    audioUri = "/data/test/media/audio/ringtone.ogg";
    ringtonePlayerImpl_->callback_ = std::make_shared<RingtonePlayerCallback>(*ringtonePlayerImpl_);
    sysSoundMgr->SetRingerMode(AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL);
    ringtonePlayerImpl_->InitPlayer(audioUri, settings, options);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_014
 * @tc.desc  : Test Start. Returns State.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_014, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    int32_t sourceId = 1;
    AudioHapticPlayerOptions options = {false, false};
    ringtonePlayerImpl_->player_ = ringtonePlayerImpl_->audioHapticManager_->CreatePlayer(sourceId, options);
    ringtonePlayerImpl_->ringtoneState_ = STATE_NEW;
    int32_t result = ringtonePlayerImpl_->Start();
    EXPECT_NE(result, 16);
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_015
 * @tc.desc  : Test Release. Returns State.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_015, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    int32_t result = ringtonePlayerImpl_->Release();
    EXPECT_EQ(result, MSERR_OK);
    result = ringtonePlayerImpl_->Release();
    EXPECT_NE(result, MSERR_OK);
    ringtonePlayerImpl_.reset();
}

/**
 * @tc.name  : Test MediaRingtonePlayer
 * @tc.number: Media_RingtonePlayer_016
 * @tc.desc  : Test Start. Returns State.
 */
HWTEST(RingtonePlayerUnitTest, Media_RingtonePlayer_016, TestSize.Level1)
{
    auto context_ = std::make_shared<ContextImpl>();
    auto sysSoundMgr = std::make_shared<SystemSoundManagerImpl>();
    RingtoneType type = RINGTONE_TYPE_SIM_CARD_0;
    auto ringtonePlayerImpl_ = std::make_shared<RingtonePlayerImpl>(context_, *sysSoundMgr, type);
    AudioStandard::InterruptEvent interruptEvent;
    ringtonePlayerImpl_->NotifyInterruptEvent(interruptEvent);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);

    ringtonePlayerImpl_->interruptCallback_ = std::make_shared<RingtonePlayerInterruptCallbackTest>();
    ringtonePlayerImpl_->NotifyInterruptEvent(interruptEvent);
    EXPECT_NE(ringtonePlayerImpl_, nullptr);
}
}
}
