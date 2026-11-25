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

#include <climits>
#include <fcntl.h>
#include <unistd.h>

#include "sound_id_manager_unit_test.h"
#include "media_errors.h"
#include "sound_id_manager.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

const int32_t MAX_STREAMS = 3;
const int32_t BEGIN_NUM = 0;
const int32_t STREAM_ID_BEGIN = 1;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundIdManagerUnitTest"};
class SoundIDManagerTestCallback : public ISoundPoolCallback {
public:
    void OnLoadCompleted(int32_t soundId) override
    {
        (void)soundId;
    }
    void OnPlayFinished(int32_t streamID) override
    {
        (void)streamID;
    }
    void OnError(int32_t errorCode) override
    {
        (void)errorCode;
    }
};
}

namespace OHOS {
namespace Media {
void SoundIDManagerUnitTest::SetUpTestCase(void)
{}

void SoundIDManagerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1);  // let PlayEngine safe exit.
}

void SoundIDManagerUnitTest::SetUp(void)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    soundIDManager_ = std::make_shared<SoundIDManager>();
}

void SoundIDManagerUnitTest::TearDown(void)
{
    if (soundIDManager_ != nullptr) {
        soundIDManager_.reset();
    }
}

/**
 * @tc.name: soundId_function_002
 * @tc.desc: function test DoLoad & Unload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_002, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_002 before");
    soundIDManager_->isParsingThreadPoolStarted_.store(false);
    EXPECT_EQ(MSERR_OK, soundIDManager_->DoLoad(0));
    soundIDManager_->soundParsers_.emplace(0, nullptr);
    EXPECT_EQ(MSERR_INVALID_VAL, soundIDManager_->Unload(1));
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(0));

    MEDIA_LOGI("soundId_function_002 after");
}

/**
 * @tc.name: soundId_function_003
 * @tc.desc: function test Load url without fd:// prefix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_003, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_003 before");
    // url without "fd://" prefix should fail
    EXPECT_EQ(-1, soundIDManager_->Load("invalid_url"));
    // empty url should fail
    EXPECT_EQ(-1, soundIDManager_->Load(""));
    MEDIA_LOGI("soundId_function_003 after");
}

/**
 * @tc.name: soundId_function_004
 * @tc.desc: function test Load url with invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_004, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_004 before");
    // fd < 0 should fail
    EXPECT_EQ(-1, soundIDManager_->Load("fd://-1"));
    EXPECT_EQ(-1, soundIDManager_->Load("fd://"));
    EXPECT_EQ(-1, soundIDManager_->Load("fd://abc"));
    MEDIA_LOGI("soundId_function_004 after");
}

/**
 * @tc.name: soundId_function_005
 * @tc.desc: function test Load url with valid fd and Unload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_005, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_005 before");
    int fd = open("/data/test/test_01.mp3", O_RDONLY);
    ASSERT_GT(fd, 0);
    std::string url = "fd://" + std::to_string(fd);
    int32_t soundID = soundIDManager_->Load(url);
    EXPECT_GT(soundID, 0);
    // GetSoundParserBySoundID should return the created parser
    std::shared_ptr<SoundParser> parser = soundIDManager_->GetSoundParserBySoundID(soundID);
    EXPECT_NE(nullptr, parser);
    EXPECT_EQ(soundID, parser->GetSoundID());
    // Unload the valid soundID
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(soundID));
    close(fd);
    MEDIA_LOGI("soundId_function_005 after");
}

/**
 * @tc.name: soundId_function_006
 * @tc.desc: function test SetApiVersion & apiVersion isolation below api18
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_006, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_006 before");
    soundIDManager_->SetApiVersion(17);
    // fill 32 parsers below api18, the 33rd load should fail
    for (int32_t i = 0; i < 32; ++i) {
        soundIDManager_->soundParsers_.emplace(i + 1, nullptr);
    }
    EXPECT_EQ(-1, soundIDManager_->Load("fd://123"));
    EXPECT_EQ(-1, soundIDManager_->Load(123, 0, 100));
    MEDIA_LOGI("soundId_function_006 after");
}

/**
 * @tc.name: soundId_function_007
 * @tc.desc: function test SetApiVersion & apiVersion isolation above api18
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_007, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_007 before");
    soundIDManager_->SetApiVersion(18);
    // fill 128 parsers above api18, the 129th load should fail
    for (int32_t i = 0; i < 128; ++i) {
        soundIDManager_->soundParsers_.emplace(i + 1, nullptr);
    }
    EXPECT_EQ(-1, soundIDManager_->Load("fd://123"));
    EXPECT_EQ(-1, soundIDManager_->Load(123, 0, 100));
    MEDIA_LOGI("soundId_function_007 after");
}

/**
 * @tc.name: soundId_function_008
 * @tc.desc: function test GetSoundParserBySoundID with empty map and non-existent soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_008, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_008 before");
    // empty map
    EXPECT_EQ(nullptr, soundIDManager_->GetSoundParserBySoundID(1));
    // non-existent soundID
    soundIDManager_->soundParsers_.emplace(1, nullptr);
    EXPECT_EQ(nullptr, soundIDManager_->GetSoundParserBySoundID(2));
    MEDIA_LOGI("soundId_function_008 after");
}

/**
 * @tc.name: soundId_function_009
 * @tc.desc: function test SetCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_009, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_009 before");
    std::shared_ptr<ISoundPoolCallback> callback;
    EXPECT_EQ(MSERR_OK, soundIDManager_->SetCallback(callback));
    MEDIA_LOGI("soundId_function_009 after");
}

/**
 * @tc.name: soundId_function_010
 * @tc.desc: function test Unload with empty map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_010, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_010 before");
    EXPECT_EQ(MSERR_NO_MEMORY, soundIDManager_->Unload(1));
    MEDIA_LOGI("soundId_function_010 after");
}

/**
 * @tc.name: soundId_function_011
 * @tc.desc: function test DoParser with empty queue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_011, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_011 before");
    // empty queue, DoParser waits for 1000ms and then exits
    EXPECT_EQ(MSERR_OK, soundIDManager_->DoParser());
    MEDIA_LOGI("soundId_function_011 after");
}

/**
 * @tc.name: soundId_function_012
 * @tc.desc: function test DoLoad when soundIDs_ queue is full
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_012, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_012 before");
    // fill the soundIDs_ queue to MAX_SOUND_ID_QUEUE(128)
    for (int32_t i = 0; i < 128; ++i) {
        soundIDManager_->soundIDs_.push_back(i + 1);
    }
    // isQuitQueue_ = false, DoLoad should wait on condition variable.
    // To avoid blocking forever, set isQuitQueue_ = true.
    soundIDManager_->isQuitQueue_ = true;
    EXPECT_EQ(MSERR_OK, soundIDManager_->DoLoad(200));
    MEDIA_LOGI("soundId_function_012 after");
}

/**
 * @tc.name: soundId_function_013
 * @tc.desc: function test Load by fd with valid fd and Unload the created parser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_013, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_013 before");
    int fd = open("/data/test/test_01.mp3", O_RDONLY);
    ASSERT_GT(fd, 0);
    int32_t soundID = soundIDManager_->Load(fd, 0, 100);
    EXPECT_GT(soundID, 0);
    std::shared_ptr<SoundParser> parser = soundIDManager_->GetSoundParserBySoundID(soundID);
    ASSERT_NE(nullptr, parser);
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(soundID));
    EXPECT_EQ(nullptr, soundIDManager_->GetSoundParserBySoundID(soundID));
    close(fd);
    MEDIA_LOGI("soundId_function_013 after");
}

/**
 * @tc.name: soundId_function_014
 * @tc.desc: function test nextSoundID_ wrap around when it reaches INT32_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_014, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_014 before");
    int fd = open("/data/test/test_01.mp3", O_RDONLY);
    ASSERT_GT(fd, 0);
    soundIDManager_->nextSoundID_ = INT32_MAX;
    int32_t soundID = soundIDManager_->Load(fd, 0, 100);
    EXPECT_EQ(1, soundID);
    EXPECT_NE(nullptr, soundIDManager_->GetSoundParserBySoundID(soundID));
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(soundID));
    close(fd);
    MEDIA_LOGI("soundId_function_014 after");
}

/**
 * @tc.name: soundId_function_015
 * @tc.desc: function test default apiVersion has no load count limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_015, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_015 before");
    // apiVersion_ keeps default value 0, so neither isolation limit applies.
    for (int32_t i = 0; i < 128; ++i) {
        soundIDManager_->soundParsers_.emplace(i + 1, nullptr);
    }
    // Start from the last occupied ID so the new ID does not collide with the placeholder entries.
    soundIDManager_->nextSoundID_ = 128;
    int fd = open("/data/test/test_01.mp3", O_RDONLY);
    ASSERT_GT(fd, 0);
    int32_t soundID = soundIDManager_->Load(fd, 0, 100);
    EXPECT_GT(soundID, 128);
    EXPECT_NE(nullptr, soundIDManager_->GetSoundParserBySoundID(soundID));
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(soundID));
    close(fd);
    MEDIA_LOGI("soundId_function_015 after");
}

/**
 * @tc.name: soundId_function_016
 * @tc.desc: function test fault apiVersion(-1) uses the above api18 load count limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_016, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_016 before");
    soundIDManager_->SetApiVersion(-1);
    for (int32_t i = 0; i < 128; ++i) {
        soundIDManager_->soundParsers_.emplace(i + 1, nullptr);
    }
    EXPECT_EQ(-1, soundIDManager_->Load("fd://123"));
    EXPECT_EQ(-1, soundIDManager_->Load(123, 0, 100));
    MEDIA_LOGI("soundId_function_016 after");
}

/**
 * @tc.name: soundId_function_017
 * @tc.desc: function test SetCallback with a valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_017, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_017 before");
    std::shared_ptr<ISoundPoolCallback> callback = std::make_shared<SoundIDManagerTestCallback>();
    EXPECT_EQ(MSERR_OK, soundIDManager_->SetCallback(callback));
    EXPECT_EQ(callback, soundIDManager_->callback_);
    MEDIA_LOGI("soundId_function_017 after");
}

/**
 * @tc.name: soundId_function_018
 * @tc.desc: function test DoParser skips a queued soundID whose parser does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_018, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_018 before");
    soundIDManager_->soundIDs_.push_back(999);
    EXPECT_EQ(MSERR_OK, soundIDManager_->DoParser());
    EXPECT_TRUE(soundIDManager_->soundIDs_.empty());
    MEDIA_LOGI("soundId_function_018 after");
}
}  // namespace Media
}  // namespace OHOS
