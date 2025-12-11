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

#include "soundpool_unit_test.h"
#include "media_errors.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

static const std::string g_fileName[6] = {
    {"/data/test/test_06.ogg"},
    {"/data/test/test_02.mp3"},
    {"/data/test/test_01.mp3"},
    {"/data/test/test_05.ogg"},
    {"/data/test/test_03.mp3"},
    {"/data/test/test_04.mp3"},
};

namespace OHOS {
namespace Media {

/**
 * @tc.name: soundpool_function_044
 * @tc.desc: function test Load Url one more time use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_044, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_044 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_044 after");
}

/**
 * @tc.name: soundpool_function_045
 * @tc.desc: function test Load Url with invalid path use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_045, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_045 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
   ASSERT_TRUE(ret == 0);
    // test invalid path
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDWR);
    std::string url = "fd://" + std::to_string(fds_[loadNum_]);
    soundIDs_[loadNum_] = soundPoolParallel_->Load(url);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Url open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_045 after");
}

/**
 * @tc.name: soundpool_function_046
 * @tc.desc: function test Load Url when no callback use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_046, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_046 before");
    int maxStreams = 3;
    create(maxStreams);
    // test no callback to load
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_046 after");
}

/**
 * @tc.name: soundpool_function_047
 * @tc.desc: function test Load Url after play use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_047, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_047 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        sleep(waitTime1);
        loadNum_++;
        loadUrlParallel(g_fileName[loadNum_], loadNum_);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_047 after");
}

/**
 * @tc.name: soundpool_function_048
 * @tc.desc: function test Load Fd one more time use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_048, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_048 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[1], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_048 after");
}

/**
 * @tc.name: soundpool_function_049
 * @tc.desc: function test Load Fd with invalid path use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_049, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_049 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDONLY);
    size_t filesize = soundPoolParallel_->GetFileSize(fileName);
    EXPECT_EQ(filesize, 0);
    soundIDs_[loadNum_] = soundPoolParallel_->Load(fds_[loadNum_], 0, filesize);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Fd open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_049 after");
}

/**
 * @tc.name: soundpool_function_050
 * @tc.desc: function test Load Fd when no callback use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_050, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_050 before");
    int maxStreams = 3;
    create(maxStreams);
    // test no callback to load
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_050 after");
}

/**
 * @tc.name: soundpool_function_051
 * @tc.desc: function test Load Fd after paly use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_051, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_051 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        sleep(waitTime1);
        loadNum_++;
        loadFdParallel(g_fileName[loadNum_], loadNum_);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_051 after");
}

/**
 * @tc.name: soundpool_function_052
 * @tc.desc: function test UnLoad use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_052, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_052 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Unload(soundIDs_[0]));
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Unload(soundIDs_[1]));
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Unload(soundIDs_[2]));
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Unload(soundIDs_[3]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_052 after");
}

/**
 * @tc.name: soundpool_function_053
 * @tc.desc: function test UnLoad with error path use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_053, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_053 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
   ASSERT_TRUE(ret == 0);
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDWR);
    std::string url = "fd://" + std::to_string(fds_[loadNum_]);
    soundIDs_[loadNum_] = soundPoolParallel_->Load(url);
    if (fds_[loadNum_] == -1) {
        cout << "Url open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    loadNum_++;
    fds_[loadNum_] = open(fileName.c_str(), O_RDONLY);
    size_t filesize = soundPoolParallel_->GetFileSize(fileName);
    EXPECT_EQ(filesize, 0);
    soundIDs_[loadNum_] = soundPoolParallel_->Load(fds_[loadNum_], 0, filesize);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Fd open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    // test UnLoad a invalid-path return soundId
    int32_t unload = soundPoolParallel_->Unload(soundIDs_[0]);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    unload = soundPoolParallel_->Unload(soundIDs_[1]);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_053 after");
}

/**
 * @tc.name: soundpool_function_054
 * @tc.desc: function test UnLoad with -1/5 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_054, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_054 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    // test unload -1
    int32_t unload = soundPoolParallel_->Unload(-1);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    // test unload 5
    unload = soundPoolParallel_->Unload(5);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_054 after");
}

/**
 * @tc.name: soundpool_function_055
 * @tc.desc: function test Play with undefault playParameters use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_055, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_055 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);

    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    playParameters.rate = 1;
    playParameters.leftVolume = 0.5;
    playParameters.rightVolume = 0.3;
    playParameters.priority = 1;
    playParameters.parallelPlayFlag = true;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_055 after");
}

/**
 * @tc.name: soundpool_function_056
 * @tc.desc: function test Play with default playParameters use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_056, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_056 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_056 after");
}

/**
 * @tc.name: soundpool_function_057
 * @tc.desc: function test Play with error soundID use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_057, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_057 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(5, playParameters);
    cout << "soundId 5 play, result: " << streamIDs_[playNum_] << endl;
    EXPECT_EQ(streamIDs_[playNum_], -1);
    sleep(waitTime1);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_057 after");
}

/**
 * @tc.name: soundpool_function_058
 * @tc.desc: function test Play with not load number -1 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_058, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_058 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(-1, playParameters);
    cout << "soundId -1 play, result: " << streamIDs_[playNum_] << endl;
    EXPECT_EQ(streamIDs_[playNum_], -1);
    sleep(waitTime1);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_058 after");
}

/**
 * @tc.name: soundpool_function_059
 * @tc.desc: function test Play with different soundID use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_059, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_059 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    sleep(waitTime1);
    playNum_++;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_059 after");
}

/**
 * @tc.name: soundpool_function_060
 * @tc.desc: function test Stop with same streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_060, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_060 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    if (streamIDs_[playNum_] > 0) {
        int32_t stopResult = soundPoolParallel_->Stop(streamIDs_[playNum_]);
        EXPECT_EQ(MSERR_OK, stopResult);
        sleep(waitTime1);
        int32_t stopResult1 = soundPoolParallel_->Stop(streamIDs_[playNum_]);
        EXPECT_NE(MSERR_OK, stopResult1);
    }
    MEDIA_LOGI("soundpool_unit_test soundpool_function_060 after");
}

/**
 * @tc.name: soundpool_function_061
 * @tc.desc: function test Stop with different streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_061, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_061 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    if (streamIDs_[0] > 0) {
        EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[0]));
    }
    if (streamIDs_[1] > 0) {
        EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[1]));
    }
    MEDIA_LOGI("soundpool_unit_test soundpool_function_061 after");
}

/**
 * @tc.name: soundpool_function_062
 * @tc.desc: function test not Stop all streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_062, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_062 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFdParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(3));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[0]));
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[2]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_062 after");
}

/**
 * @tc.name: soundpool_function_063
 * @tc.desc: function test Stop with -1 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_063, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_063 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    int32_t stopResult = soundPoolParallel_->Stop(-1);
    EXPECT_EQ(MSERR_INVALID_OPERATION, stopResult);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_063 after");
}

/**
 * @tc.name: soundpool_function_064
 * @tc.desc: function test SetLoop use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_064, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_064 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Unload(soundIDs_[loadNum_]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_064 after");
}

/**
 * @tc.name: soundpool_function_065
 * @tc.desc: function test SetLoop 3 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_065, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_065 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = 3;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_065 after");
}

/**
 * @tc.name: soundpool_function_066
 * @tc.desc: function test SetLoop -2 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_066, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_066 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -2;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_066 after");
}

/**
 * @tc.name: soundpool_function_067
 * @tc.desc: function test SetLoop -1, streamID is -1 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_067, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_067 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(-1, loop);
        EXPECT_EQ(MSERR_INVALID_OPERATION, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_067 after");
}

/**
 * @tc.name: soundpool_function_068
 * @tc.desc: function test SetLoop 2 with different streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_068, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_068 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    int32_t loop = 2;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool1 = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_068 after");
}

/**
 * @tc.name: soundpool_function_069
 * @tc.desc: function test SetLoop different loop with different streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_069, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_069 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    int32_t loop = 2;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPoolParallel_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool1 = soundPoolParallel_->SetLoop(streamIDs_[playNum_], -1);
        EXPECT_EQ(MSERR_OK, setPool1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_069 after");
}

/**
 * @tc.name: soundpool_function_070
 * @tc.desc: function test SetRate with different rate use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_070, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_070 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t result = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, result);
        sleep(waitTime3);
        int32_t result1 = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_HALF);
        EXPECT_EQ(MSERR_OK, result1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }

    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_070 after");
}

/**
 * @tc.name: soundpool_function_071
 * @tc.desc: function test SetRate with different rate and streamID use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_071, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_071 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t result = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, result);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t result = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_HALF);
        EXPECT_EQ(MSERR_OK, result);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_071 after");
}

/**
 * @tc.name: soundpool_function_072
 * @tc.desc: function test SetRate with different streamID and same rate use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_072, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_072 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t result = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, result);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t result = soundPoolParallel_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, result);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_072 after");
}

/**
 * @tc.name: soundpool_function_073
 * @tc.desc: function test SetVolume 0.5 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_073, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_073 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = 0.5;
    float rightVolume = 0.5;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_073 after");
}

/**
 * @tc.name: soundpool_function_074
 * @tc.desc: function test SetVolume deifferent leftVolume use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_074, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_074 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = 0.1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, 0.0);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime3);
        int32_t setVol1 = soundPoolParallel_->SetVolume(streamIDs_[playNum_], 1.0, 0.0);
        EXPECT_EQ(MSERR_OK, setVol1);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_074 after");
}

/**
 * @tc.name: soundpool_function_075
 * @tc.desc: function test SetVolume leftVolume -1 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_075, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_075 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, 0.0);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_075 after");
}

/**
 * @tc.name: soundpool_function_076
 * @tc.desc: function test SetVolume rightVolume 2.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_076, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_076 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float rightVolume = 2.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], 0.0, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_076 after");
}

/**
 * @tc.name: soundpool_function_077
 * @tc.desc: function test SetPriority 1 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_077, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_077 before");
    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    int32_t priority  = 1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[playNum_], priority);
        EXPECT_EQ(MSERR_OK, setPriority);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_077 after");
}


/**
 * @tc.name: soundpool_function_078
 * @tc.desc: function test SetPriority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_078, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_078 before");
    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.priority = 1;
    playParameters.loop = -1;
    int32_t priority  = -1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
    }
    int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[0], priority);
    sleep(waitTime1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[1], 0);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_078 after");
}

/**
 * @tc.name: soundpool_function_079
 * @tc.desc: function test Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_079, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_079 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[0], loadNum_);
    sleep(waitTime3);
    struct PlayParams playParameters;
    playParameters.priority = 3;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    playParameters.priority = 5;
    if (soundIDs_[3] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[3], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    sleep(waitTime10);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_079 after");
}

/**
 * @tc.name: soundpool_function_080
 * @tc.desc: function test Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_080, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_080 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrlParallel(g_fileName[0], loadNum_);
    sleep(waitTime3);
    struct PlayParams playParameters;
    playParameters.priority = 3;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    playParameters.priority = 1;
    if (soundIDs_[3] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[3], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    sleep(waitTime10);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_080 after");
}


/**
 * @tc.name: soundpool_function_081
 * @tc.desc: function test MaxStreams use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_081, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_081 before");

    int maxStreams = 3;
    create(maxStreams);
    maxStreams = -1;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_FALSE(soundPoolParallel_->CreateParallelSoundPool(maxStreams, audioRenderInfo));
    maxStreams = 256;
    EXPECT_TRUE(soundPoolParallel_->CreateParallelSoundPool(maxStreams, audioRenderInfo));

    MEDIA_LOGI("soundpool_unit_test soundpool_function_081 after");
}

/**
 * @tc.name: soundpool_function_082
 * @tc.desc: function test AudioStream DoPlay fail use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_082, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_082 before");

    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[1], loadNum_);
    sleep(waitTime3);
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();

    MEDIA_LOGI("soundpool_unit_test soundpool_function_082 after");
}

/**
 * @tc.name: soundpool_function_083
 * @tc.desc: function test play Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_083, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_083 before");

    int maxStreams = 4;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[2], loadNum_++);
    loadUrlParallel(g_fileName[1], loadNum_++);
    loadUrlParallel(g_fileName[4], loadNum_++);
    loadUrlParallel(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[3], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[3], 4);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime10);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_083 after");
}

/**
 * @tc.name: soundpool_function_084
 * @tc.desc: function test willplay Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_084, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_084 before");

    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[2], loadNum_++);
    loadUrlParallel(g_fileName[1], loadNum_++);
    loadUrlParallel(g_fileName[4], loadNum_++);
    loadUrlParallel(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[3], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[3], 4);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime30);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_084 after");
}


/**
 * @tc.name: soundpool_function_085
 * @tc.desc: function test playFinished with streamId use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_085, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_085 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[4], loadNum_++);
    loadUrlParallel(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    sleep(waitTime1);
    playNum_++;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t totalNum = playNum_ + 1;
    int32_t matchNum = 0;
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[0]));
    EXPECT_EQ(MSERR_OK, soundPoolParallel_->Stop(streamIDs_[1]));

    std::vector<int32_t> vector = cb->GetHavePlayedStreamID();
    EXPECT_EQ(totalNum, vector.size());
    for (int32_t i = 0; i < totalNum; ++i) {
        for (int32_t playStreamId : vector) {
            if (playStreamId == streamIDs_[i]) {
                matchNum++;
            }
        }
    }
    EXPECT_EQ(totalNum, matchNum);

    cb->ResetHavePlayedStreamID();
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_085 after");
}

/**
 * @tc.name: soundpool_function_086
 * @tc.desc: function test soundpool multi instance use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_086, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_086 before");
    int maxStreams = 3;
    create(maxStreams);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;

    std::shared_ptr<SoundPoolParallelMock> soundPoolParallel1 = std::make_shared<SoundPoolParallelMock>();
    std::shared_ptr<SoundPoolParallelMock> soundPoolParallel2 = std::make_shared<SoundPoolParallelMock>();
    EXPECT_TRUE(soundPoolParallel1->CreateParallelSoundPool(maxStreams, audioRenderInfo));
    EXPECT_TRUE(soundPoolParallel2->CreateParallelSoundPool(maxStreams, audioRenderInfo));
    std::shared_ptr<SoundPoolCallbackTest> cb1 = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel1);
    soundPoolParallel1->SetSoundPoolCallback(cb1);
    std::shared_ptr<SoundPoolCallbackTest> cb2 = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel2);
    soundPoolParallel2->SetSoundPoolCallback(cb2);

    functionTest086(soundPoolParallel1, soundPoolParallel2, cb1, cb2);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_086 after");
}

void SoundPoolUnitTest::functionTest086(std::shared_ptr<SoundPoolParallelMock> soundPool1,
    std::shared_ptr<SoundPoolParallelMock> soundPool2, std::shared_ptr<SoundPoolCallbackTest> cb1,
    std::shared_ptr<SoundPoolCallbackTest> cb2)
{
    int32_t soundNum = 2;
    int32_t num0 = 0;
    int32_t num1 = 1;
    int32_t num2 = 2;
    int32_t num3 = 3;
    fds_[num0] = open(g_fileName[num0].c_str(), O_RDWR);
    fds_[num1] = open(g_fileName[num1].c_str(), O_RDWR);
    std::string url0 = "fd://" + std::to_string(fds_[num0]);
    std::string url1 = "fd://" + std::to_string(fds_[num1]);
    soundIDs_[num0] = soundPool1->Load(url0);
    soundIDs_[num1] = soundPool1->Load(url1);
    EXPECT_GT(soundIDs_[num0], 0);
    EXPECT_GT(soundIDs_[num1], 0);
    
    fds_[num2] = open(g_fileName[num2].c_str(), O_RDWR);
    fds_[num3] = open(g_fileName[num3].c_str(), O_RDWR);
    std::string url2 = "fd://" + std::to_string(fds_[num2]);
    std::string url3 = "fd://" + std::to_string(fds_[num3]);
    soundIDs_[num2] = soundPool2->Load(url2);
    soundIDs_[num3] = soundPool2->Load(url3);
    EXPECT_GT(soundIDs_[num2], 0);
    EXPECT_GT(soundIDs_[num3], 0);
    sleep(waitTime3);

    struct PlayParams playParameters;
    streamIDs_[num0] = soundPool1->Play(soundIDs_[num0], playParameters);
    streamIDs_[num1] = soundPool1->Play(soundIDs_[num1], playParameters);
    EXPECT_GT(streamIDs_[num0], 0);
    EXPECT_GT(streamIDs_[num1], 0);
    streamIDs_[num2] = soundPool2->Play(soundIDs_[num2], playParameters);
    streamIDs_[num3] = soundPool2->Play(soundIDs_[num3], playParameters);
    EXPECT_GT(streamIDs_[num2], 0);
    EXPECT_GT(streamIDs_[num3], 0);

    sleep(waitTime20);

    ASSERT_TRUE(cb1->WaitLoadedSoundNum(soundNum));
    EXPECT_EQ(soundNum, cb1->GetHavePlayedSoundNum());
    ASSERT_TRUE(cb2->WaitLoadedSoundNum(soundNum));
    EXPECT_EQ(soundNum, cb2->GetHavePlayedSoundNum());

    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num3]));

    EXPECT_EQ(MSERR_OK, soundPool1->Release());
    EXPECT_EQ(MSERR_OK, soundPool2->Release());
}

/**
 * @tc.name: soundpool_function_087
 * @tc.desc: function test willplay Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_087, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_087 before");

    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[2], loadNum_++);
    loadUrlParallel(g_fileName[1], loadNum_++);
    loadUrlParallel(g_fileName[4], loadNum_++);
    loadUrlParallel(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[3], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[3], 4);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime20);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_087 after");
}


/**
 * @tc.name: soundpool_function_088
 * @tc.desc: function test willplay Priority use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_088, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_088 before");

    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    soundPoolParallel_->SetSoundPoolCallback(cb);
    loadUrlParallel(g_fileName[2], loadNum_++);
    loadUrlParallel(g_fileName[1], loadNum_++);
    loadUrlParallel(g_fileName[4], loadNum_++);
    loadUrlParallel(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPoolParallel_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPoolParallel_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime20);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_088 after");
}

/**
 * @tc.name: soundpool_function_089
 * @tc.desc: function test SetVolume rightVolume 3.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_089, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_089 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    while (true) {
        if (cb->GetHaveLoadedSoundNum() == 1) {
            cout << "All sound loaded Url break. loaded sound num = " << cb->GetHaveLoadedSoundNum()  << endl;
            cb->ResetHaveLoadedSoundNum();
            break;
        }
    }
    struct PlayParams playParameters;
    float rightVolume = 3.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_089 after");
}

/**
 * @tc.name: soundpool_function_090
 * @tc.desc: function test SetVolume leftVolume 3.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_090, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_090 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    while (true) {
        if (cb->GetHaveLoadedSoundNum() == 1) {
            cout << "All sound loaded Url break. loaded sound num = " << cb->GetHaveLoadedSoundNum()  << endl;
            cb->ResetHaveLoadedSoundNum();
            break;
        }
    }
    struct PlayParams playParameters;
    float leftVolume = 3.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, 0.0);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_090 after");
}

/**
 * @tc.name: soundpool_function_091
 * @tc.desc: function test SetVolume 2.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_091, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_091 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    while (true) {
        if (cb->GetHaveLoadedSoundNum() == 1) {
            cout << "All sound loaded Url break. loaded sound num = " << cb->GetHaveLoadedSoundNum()  << endl;
            cb->ResetHaveLoadedSoundNum();
            break;
        }
    }
    struct PlayParams playParameters;
    float leftVolume = 2.0;
    float rightVolume = 2.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_091 after");
}

/**
 * @tc.name: soundpool_function_092
 * @tc.desc: function test SetVolume 1.0, 2.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_092, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_092 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    while (true) {
        if (cb->GetHaveLoadedSoundNum() == 1) {
            cout << "All sound loaded Url break. loaded sound num = " << cb->GetHaveLoadedSoundNum()  << endl;
            cb->ResetHaveLoadedSoundNum();
            break;
        }
    }
    struct PlayParams playParameters;
    float leftVolume = 1.0;
    float rightVolume = 2.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_092 after");
}

/**
 * @tc.name: soundpool_function_093
 * @tc.desc: function test SetVolume 2.0, 1.0 use soundPoolParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_093, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_093 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPoolParallel_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPoolParallel_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrlParallel(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    while (true) {
        if (cb->GetHaveLoadedSoundNum() == 1) {
            cout << "All sound loaded Url break. loaded sound num = " << cb->GetHaveLoadedSoundNum()  << endl;
            cb->ResetHaveLoadedSoundNum();
            break;
        }
    }
    struct PlayParams playParameters;
    float leftVolume = 2.0;
    float rightVolume = 1.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPoolParallel_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPoolParallel_->SetVolume(streamIDs_[playNum_], leftVolume, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_093 after");
}
} // namespace Media
} // namespace OHOS