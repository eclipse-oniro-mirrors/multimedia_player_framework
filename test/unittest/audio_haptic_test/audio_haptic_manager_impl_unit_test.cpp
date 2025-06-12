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

#include "audio_haptic_manager_impl_unit_test.h"

#include "audio_haptic_player_impl.h"
#include "audio_haptic_test_common.h"

#include "media_errors.h"
#include <fcntl.h>
#include <sys/stat.h>

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

const std::string AUDIO_TEST_URI = "ringtone.ogg";
const std::string HAPTIC_TEST_URI = "ringtone.json";
const std::string HAPTIC_TEST_EFFECT_ID = "haptic.clock.timer";

static std::shared_ptr<AudioHapticManagerImpl> g_audioHapticManagerImpl = nullptr;

void AudioHapticManagerImplUnitTest::SetUpTestCase(void)
{
    ASSERT_NE(GetAllPermission(), 0);

    g_audioHapticManagerImpl = std::make_shared<AudioHapticManagerImpl>();
    ASSERT_NE(g_audioHapticManagerImpl, nullptr);
}

void AudioHapticManagerImplUnitTest::TearDownTestCase(void)
{
}

void AudioHapticManagerImplUnitTest::SetUp(void) {}

void AudioHapticManagerImplUnitTest::TearDown(void) {}

/**
* @tc.name  : Test AudioHapticManagerImpl RegisterSource API
* @tc.number: AudioHapticManagerImpl_RegisterSource_001
* @tc.desc  : Test AudioHapticManagerImpl RegisterSource interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_RegisterSource_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl RegisterSourceWithEffectId API
* @tc.number: AudioHapticManagerImpl_RegisterSourceWithEffectId_001
* @tc.desc  : Test AudioHapticManagerImpl RegisterSourceWithEffectId interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_RegisterSourceWithEffectId_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string effectId = HAPTIC_TEST_EFFECT_ID;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceWithEffectId(audioUri, effectId);
    EXPECT_NE(-1, sourceId);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl UnregisterSource API
* @tc.number: AudioHapticManagerImpl_UnregisterSource_001
* @tc.desc  : Test AudioHapticManagerImpl UnregisterSource interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_UnregisterSource_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = g_audioHapticManagerImpl->UnregisterSource(sourceId);
    EXPECT_EQ(MSERR_OK, result);
}

/**
* @tc.name  : Test AudioHapticManagerImpl UnregisterSource API
* @tc.number: AudioHapticManagerImpl_UnregisterSource_002
* @tc.desc  : Test AudioHapticManagerImpl UnregisterSource interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_UnregisterSource_002, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    int32_t sourceId = -1;
    int32_t result = g_audioHapticManagerImpl->UnregisterSource(sourceId);
    EXPECT_NE(MSERR_OK, result);
}

/**
* @tc.name  : Test AudioHapticManagerImpl UnregisterSource API
* @tc.number: AudioHapticManagerImpl_UnregisterSource_003
* @tc.desc  : Test AudioHapticManagerImpl UnregisterSource interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_UnregisterSource_003, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string effectId = HAPTIC_TEST_EFFECT_ID;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceWithEffectId(audioUri, effectId);
    EXPECT_NE(-1, sourceId);

    int32_t result = g_audioHapticManagerImpl->UnregisterSource(sourceId);
    EXPECT_EQ(MSERR_OK, result);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetAudioLatencyMode API
* @tc.number: AudioHapticManagerImpl_SetAudioLatencyMode_001
* @tc.desc  : Test AudioHapticManagerImpl SetAudioLatencyMode interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetAudioLatencyMode_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_FAST;
    int32_t result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetAudioLatencyMode API
* @tc.number: AudioHapticManagerImpl_SetAudioLatencyMode_002
* @tc.desc  : Test AudioHapticManagerImpl SetAudioLatencyMode interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetAudioLatencyMode_002, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    int32_t result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetAudioLatencyMode API
* @tc.number: AudioHapticManagerImpl_SetAudioLatencyMode_003
* @tc.desc  : Test AudioHapticManagerImpl SetAudioLatencyMode interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetAudioLatencyMode_003, TestSize.Level1)
{
    int32_t sourceId = -1;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    int32_t result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_NE(MSERR_OK, result);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetAudioLatencyMode API
* @tc.number: AudioHapticManagerImpl_SetAudioLatencyMode_004
* @tc.desc  : Test AudioHapticManagerImpl SetAudioLatencyMode interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetAudioLatencyMode_004, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string effectId = HAPTIC_TEST_EFFECT_ID;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceWithEffectId(audioUri, effectId);
    EXPECT_NE(-1, sourceId);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    int32_t result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_NE(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetAudioLatencyMode API
* @tc.number: AudioHapticManagerImpl_SetAudioLatencyMode_005
* @tc.desc  : Test AudioHapticManagerImpl SetAudioLatencyMode interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetAudioLatencyMode_005, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string effectId = HAPTIC_TEST_EFFECT_ID;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceWithEffectId(audioUri, effectId);
    EXPECT_NE(-1, sourceId);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_FAST;
    int32_t result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetStreamUsage API
* @tc.number: AudioHapticManagerImpl_SetStreamUsage_001
* @tc.desc  : Test AudioHapticManagerImpl SetStreamUsage interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetStreamUsage_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetStreamUsage API
* @tc.number: AudioHapticManagerImpl_SetStreamUsage_002
* @tc.desc  : Test AudioHapticManagerImpl SetStreamUsage interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetStreamUsage_002, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetStreamUsage API
* @tc.number: AudioHapticManagerImpl_SetStreamUsage_003
* @tc.desc  : Test AudioHapticManagerImpl SetStreamUsage interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetStreamUsage_003, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetStreamUsage API
* @tc.number: AudioHapticManagerImpl_SetStreamUsage_004
* @tc.desc  : Test AudioHapticManagerImpl SetStreamUsage interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetStreamUsage_004, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_NE(MSERR_OK, result);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl SetStreamUsage API
* @tc.number: AudioHapticManagerImpl_SetStreamUsage_005
* @tc.desc  : Test AudioHapticManagerImpl SetStreamUsage interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_SetStreamUsage_005, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = -1;
    int32_t result = MSERR_OK;

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_NE(MSERR_OK, result);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_001
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_001, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    AudioHapticPlayerOptions options;
    options.muteAudio = false;
    options.muteHaptics = false;
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, audioHapticPlayer);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_002
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_002, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    AudioHapticPlayerOptions options;
    options.muteAudio = true;
    options.muteHaptics = false;
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, audioHapticPlayer);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_003
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_003, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    AudioHapticPlayerOptions options;
    options.muteAudio = false;
    options.muteHaptics = true;
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, audioHapticPlayer);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_004
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_004, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, hapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    AudioHapticPlayerOptions options;
    options.muteAudio = true;
    options.muteHaptics = true;
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, audioHapticPlayer);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_005
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_005, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    AudioHapticPlayerOptions options;
    options.muteAudio = false;
    options.muteHaptics = false;
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        g_audioHapticManagerImpl->CreatePlayer(-1, options);
    EXPECT_EQ(nullptr, audioHapticPlayer);
}

/**
* @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
* @tc.number: AudioHapticManagerImpl_CreatePlayer_006
* @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
*/
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_006, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;
    int32_t fd = open(hapticUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, fd);
    std::string newHapticUri = "fd://" + to_string(fd);

    int32_t sourceId = g_audioHapticManagerImpl->RegisterSource(audioUri, newHapticUri);
    EXPECT_NE(-1, sourceId);

    int32_t result = MSERR_OK;
    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    result = g_audioHapticManagerImpl->SetAudioLatencyMode(sourceId, latencyMode);
    EXPECT_EQ(MSERR_OK, result);

    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    result = g_audioHapticManagerImpl->SetStreamUsage(sourceId, streamUsage);
    EXPECT_EQ(MSERR_OK, result);

    AudioHapticPlayerOptions options = {false, false};
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
    g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, audioHapticPlayer);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
 * @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
 * @tc.number: AudioHapticManagerImpl_CreatePlayer_007
 * @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
 */
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_007, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;

    int32_t audioFd = open(audioUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, audioFd);
    struct stat64 audioBuff = { 0 };
    int ret = fstat64(audioFd, &audioBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor audioFile;
    audioFile.fd = audioFd;
    audioFile.offset = 0;
    audioFile.length = audioBuff.st_size;

    int32_t hapticDd = open(hapticUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, hapticDd);
    struct stat64 hatpicBuff = { 0 };
    ret = fstat64(hapticDd, &hatpicBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor hapticFile;
    hapticFile.fd = hapticDd;
    hapticFile.offset = 0;
    hapticFile.length = hatpicBuff.st_size;

    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_NE(-1, sourceId);

    AudioHapticPlayerOptions options = {false, false};
    auto player = g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    EXPECT_NE(nullptr, player);

    player->Release();
    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
 * @tc.name  : Test AudioHapticManagerImpl CreatePlayer API
 * @tc.number: AudioHapticManagerImpl_CreatePlayer_008
 * @tc.desc  : Test AudioHapticManagerImpl CreatePlayer interface
 */
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_CreatePlayer_008, TestSize.Level1)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;

    int32_t audioFd = open(audioUri.c_str(), O_RDONLY);
    EXPECT_NE(FILE_DESCRIPTOR_INVALID, audioFd);
    struct stat64 audioBuff = { 0 };
    int ret = fstat64(audioFd, &audioBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor audioFile;
    audioFile.fd = audioFd;
    audioFile.offset = 0;
    audioFile.length = audioBuff.st_size;

    int32_t hapticDd = open(hapticUri.c_str(), O_RDONLY);
    EXPECT_NE(FILE_DESCRIPTOR_INVALID, hapticDd);
    struct stat64 hatpicBuff = { 0 };
    ret = fstat64(hapticDd, &hatpicBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor hapticFile;
    hapticFile.fd = hapticDd;
    hapticFile.offset = 0;
    hapticFile.length = hatpicBuff.st_size;

    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_NE(INVALID_SOURCE_ID, sourceId);

    AudioHapticPlayerOptions options = {false, false};
    auto player1 = g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    auto playerImpl1 = static_cast<AudioHapticPlayerImpl*>(player1.get());
    EXPECT_NE(nullptr, playerImpl1);

    auto player2 = g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    auto playerImpl2 = static_cast<AudioHapticPlayerImpl*>(player2.get());
    EXPECT_NE(nullptr, playerImpl2);

    EXPECT_NE(playerImpl1->audioHapticSyncId_, playerImpl2->audioHapticSyncId_);

    player1->Release();
    player2->Release();
    g_audioHapticManagerImpl->UnregisterSource(sourceId);
}

/**
 * @tc.name  : Test AudioHapticManagerImpl RegisterSourceFromFd API
 * @tc.number: AudioHapticManagerImpl_RegisterSourceFromFd_001
 * @tc.desc  : Test AudioHapticManagerImpl RegisterSourceFromFd Success
 */
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_RegisterSourceFromFd_001, TestSize.Level0)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;

    int32_t audioFd = open(audioUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, audioFd);
    struct stat64 audioBuff = { 0 };
    int ret = fstat64(audioFd, &audioBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor audioFile;
    audioFile.fd = audioFd;
    audioFile.offset = 0;
    audioFile.length = audioBuff.st_size;

    int32_t hapticDd = open(hapticUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, hapticDd);
    struct stat64 hatpicBuff = { 0 };
    ret = fstat64(hapticDd, &hatpicBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor hapticFile;
    hapticFile.fd = hapticDd;
    hapticFile.offset = 0;
    hapticFile.length = hatpicBuff.st_size;

    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_NE(-1, sourceId);

    g_audioHapticManagerImpl->UnregisterSource(sourceId);
    close(audioFd);
    close(hapticDd);
}

/**
 * @tc.name  : Test AudioHapticManagerImpl RegisterSourceFromFd API
 * @tc.number: AudioHapticManagerImpl_RegisterSourceFromFd_002
 * @tc.desc  : Test AudioHapticManagerImpl RegisterSourceFromFd Error Fd
 */
HWTEST_F(AudioHapticManagerImplUnitTest, AudioHapticManagerImpl_RegisterSourceFromFd_002, TestSize.Level0)
{
    EXPECT_NE(g_audioHapticManagerImpl, nullptr);

    std::string audioUri = AUDIO_TEST_URI;
    std::string hapticUri = HAPTIC_TEST_URI;

    int32_t audioFd = open(audioUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, audioFd);
    struct stat64 audioBuff = { 0 };
    int ret = fstat64(audioFd, &audioBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor audioFile;
    audioFile.fd = audioFd;
    audioFile.offset = 0;
    audioFile.length = audioBuff.st_size;

    int32_t hapticDd = open(hapticUri.c_str(), O_RDONLY);
    EXPECT_NE(-1, hapticDd);
    struct stat64 hatpicBuff = { 0 };
    ret = fstat64(hapticDd, &hatpicBuff);
    EXPECT_EQ(0, ret);
    AudioHapticFileDescriptor hapticFile;
    hapticFile.fd = hapticDd;
    hapticFile.offset = 0;
    hapticFile.length = hatpicBuff.st_size;

    g_audioHapticManagerImpl->curPlayerCount_ = 128;
    int32_t sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_EQ(-1, sourceId);

    g_audioHapticManagerImpl->curPlayerCount_ = 0;
    audioFile.fd = -1;
    sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_EQ(-1, sourceId);

    audioFile.fd = audioFd;
    hapticFile.fd = -1;
    sourceId = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    EXPECT_EQ(-1, sourceId);

    close(audioFd);
    close(hapticDd);
}
} // namespace Media
} // namespace OHOS