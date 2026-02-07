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

#include "media_errors.h"
#include "system_sound_player_unit_test.h"
#include "system_sound_player_impl.h"

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void SystemSoundPlayerUnitTest::SetUpTestCase(void) {}
void SystemSoundPlayerUnitTest::TearDownTestCase(void) {}
void SystemSoundPlayerUnitTest::SetUp(void) {}
void SystemSoundPlayerUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_001
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_001, TestSize.Level1)
{
    bool ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    ret = systemSoundPlayerImpl_->IsSystemSoundTypeValid(systemSoundType);
    EXPECT_TRUE(ret);
    systemSoundType = VIDEO_RECORDING_BEGIN;
    ret = systemSoundPlayerImpl_->IsSystemSoundTypeValid(systemSoundType);
    EXPECT_TRUE(ret);
    systemSoundType = VIDEO_RECORDING_END;
    ret = systemSoundPlayerImpl_->IsSystemSoundTypeValid(systemSoundType);
    EXPECT_TRUE(ret);
    ret = systemSoundPlayerImpl_->IsSystemSoundTypeValid(static_cast<SystemSoundType>(-1));
    EXPECT_FALSE(ret);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_002
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_002, TestSize.Level1)
{
    bool ret = false;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRenderInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_ENFORCED_TONE;
    audioRenderInfo.rendererFlags = AudioStandard::AUDIO_FLAG_MMAP;
    audioRenderInfo.playerType = AudioStandard::PLAYER_TYPE_SYSTEM_SOUND_PLAYER;
    systemSoundPlayerImpl_->soundPool_ =
        SoundPoolFactory::CreateSoundPool(1, audioRenderInfo);
    ret = systemSoundPlayerImpl_->InitSoundPoolPlayer();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_003
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_003, TestSize.Level1)
{
    bool ret = false;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    ret = systemSoundPlayerImpl_->InitSoundPoolPlayer();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_004
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_004, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    ret = systemSoundPlayerImpl_->Load(static_cast<SystemSoundType>(-1));
    EXPECT_NE(ret, 0);

    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    systemSoundPlayerImpl_->isReleased_ = false;
    ret = systemSoundPlayerImpl_->Load(systemSoundType);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_005
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_005, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    systemSoundPlayerImpl_->isReleased_ = true;
    ret = systemSoundPlayerImpl_->Load(systemSoundType);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_006
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_006, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    ret = systemSoundPlayerImpl_->Play(static_cast<SystemSoundType>(-1));
    EXPECT_NE(ret, 0);

    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    systemSoundPlayerImpl_->isReleased_ = false;
    ret = systemSoundPlayerImpl_->Play(systemSoundType);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_007
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_007, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    SystemSoundType systemSoundType = VIDEO_RECORDING_BEGIN;
    systemSoundPlayerImpl_->isReleased_ = true;
    ret = systemSoundPlayerImpl_->Play(systemSoundType);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_008
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_008, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    systemSoundPlayerImpl_->isReleased_ = false;
    ret = systemSoundPlayerImpl_->Unload(systemSoundType);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_009
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_009, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();

    ret = systemSoundPlayerImpl_->Unload(static_cast<SystemSoundType>(-1));
    EXPECT_NE(ret, 0);

    SystemSoundType systemSoundType = PHOTO_SHUTTER;
    systemSoundPlayerImpl_->isReleased_ = true;
    ret = systemSoundPlayerImpl_->Unload(systemSoundType);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_010
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_010, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    systemSoundPlayerImpl_->isReleased_ = false;
    ret = systemSoundPlayerImpl_->Release();
    EXPECT_EQ(ret, 0);

    systemSoundPlayerImpl_->isReleased_ = true;
    ret = systemSoundPlayerImpl_->Release();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_011
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_011, TestSize.Level1)
{
    int32_t ret = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    int32_t MAX_SOUND_POOL_STREAMS = 1;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRenderInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_ENFORCED_TONE;
    audioRenderInfo.rendererFlags = AudioStandard::AUDIO_FLAG_MMAP;
    audioRenderInfo.playerType = AudioStandard::PLAYER_TYPE_SYSTEM_SOUND_PLAYER;
    systemSoundPlayerImpl_->soundPool_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRenderInfo);
    ret = systemSoundPlayerImpl_->Release();
    EXPECT_EQ(ret, 0);

    systemSoundPlayerImpl_->soundPool_  = nullptr;
    ret = systemSoundPlayerImpl_->Release();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_012
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_012, TestSize.Level1)
{
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    auto playerSoundPoolCallback = std::make_shared<PlayerSoundPoolCallback>(systemSoundPlayerImpl_);
    int32_t soundId = 0;
    playerSoundPoolCallback->OnLoadCompleted(soundId);
    EXPECT_NE(systemSoundPlayerImpl_, nullptr);
    systemSoundPlayerImpl_ = nullptr;
    playerSoundPoolCallback->OnLoadCompleted(soundId);
    EXPECT_EQ(systemSoundPlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_013
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_013, TestSize.Level1)
{
    int32_t streamId = 0;
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    auto playerSoundPoolCallback = std::make_shared<PlayerSoundPoolCallback>(systemSoundPlayerImpl_);
    playerSoundPoolCallback->OnPlayFinished(streamId);
    EXPECT_NE(systemSoundPlayerImpl_, nullptr);
    systemSoundPlayerImpl_ = nullptr;
    playerSoundPoolCallback->OnPlayFinished(streamId);
    EXPECT_EQ(systemSoundPlayerImpl_, nullptr);
}

/**
 * @tc.name  : Test SystemSoundPlayer
 * @tc.number: systemSoundPlayer_014
 * @tc.desc  : Test systemSoundPlayer interface.
 */
HWTEST(SystemSoundPlayerUnitTest, systemSoundPlayer_014, TestSize.Level1)
{
    auto systemSoundPlayerImpl_ = std::make_shared<SystemSoundPlayerImpl>();
    auto playerSoundPoolCallback = std::make_shared<PlayerSoundPoolCallback>(systemSoundPlayerImpl_);
    int32_t errorCode = 0;
    playerSoundPoolCallback->OnError(errorCode);
    EXPECT_NE(systemSoundPlayerImpl_, nullptr);
    systemSoundPlayerImpl_ = nullptr;
    playerSoundPoolCallback->OnError(errorCode);
    EXPECT_EQ(systemSoundPlayerImpl_, nullptr);
}
} // namespace Media
} // namespace OHOS