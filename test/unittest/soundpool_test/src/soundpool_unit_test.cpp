/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "stream_id_manager.h"

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

const int32_t MAX_STREAMS = 3;

namespace OHOS {
namespace Media {
void SoundPoolUnitTest::SetUpTestCase(void) {}

void SoundPoolUnitTest::TearDownTestCase(void) {}

void SoundPoolUnitTest::SetUp(void)
{
    soundPool_ = std::make_shared<SoundPoolMock>();
    ASSERT_NE(nullptr, soundPool_);
    soundPoolParallel_ = std::make_shared<SoundPoolParallelMock>();
    ASSERT_NE(nullptr, soundPoolParallel_);
}

void SoundPoolUnitTest::TearDown(void)
{
    for (auto soundId : soundIDs_) {
        if (soundId != 0) {
            soundId = 0;
        }
    }
    for (auto streamId : streamIDs_) {
        if (streamId != 0) {
            streamId = 0;
        }
    }
    for (auto fd : fds_) {
        if (fd != 0) {
            fd = 0;
        }
    }
    if (loadNum_ != 0 || playNum_ != 0) {
        loadNum_ = 0;
        playNum_ = 0;
    }

    if (soundPool_ != nullptr) {
        int32_t ret = soundPool_->Release();
        soundPool_ = nullptr;
        EXPECT_EQ(MSERR_OK, ret);
    }
    if (soundPoolParallel_ != nullptr) {
        int32_t ret = soundPoolParallel_->Release();
        soundPoolParallel_ = nullptr;
        EXPECT_EQ(MSERR_OK, ret);
    }
    sleep(waitTime1);
}

void SoundPoolUnitTest::create(int maxStreams)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    if (soundPool_ == nullptr) {
        cout << "create soundpool failed" << endl;
    } else {
        EXPECT_TRUE(soundPool_->CreateSoundPool(maxStreams, audioRenderInfo));
    }
    if (soundPoolParallel_ == nullptr) {
        cout << "create soundPoolParallel_ failed" << endl;
    } else {
        EXPECT_TRUE(soundPoolParallel_->CreateParallelSoundPool(maxStreams, audioRenderInfo));
    }
}

void SoundPoolUnitTest::loadUrl(std::string fileName, int32_t loadNum)
{
    fds_[loadNum] = open(fileName.c_str(), O_RDWR);
    if (fds_[loadNum] > 0) {
        std::string url = "fd://" + std::to_string(fds_[loadNum]);
        soundIDs_[loadNum] = soundPool_->Load(url);
    } else {
        cout << "Url open failed, g_fileName " << fileName.c_str() << ", fd: " << fds_[loadNum] << endl;
    }
    EXPECT_GT(soundIDs_[loadNum], 0);
}

void SoundPoolUnitTest::loadFd(std::string fileName, int32_t loadNum)
{
    fds_[loadNum] = open(fileName.c_str(), O_RDONLY);
    if (fds_[loadNum] < 0) {
        cout << "Fd open failed, g_fileName " << fileName.c_str() << ", Fd: " << fds_[loadNum] << endl;
    }
    size_t filesize = soundPool_->GetFileSize(fileName);
    EXPECT_NE(filesize, 0);
    soundIDs_[loadNum] = soundPool_->Load(fds_[loadNum], 0, filesize);
    EXPECT_GT(soundIDs_[loadNum], 0);
}

void SoundPoolUnitTest::loadUrlParallel(std::string fileName, int32_t loadNum)
{
    fds_[loadNum] = open(fileName.c_str(), O_RDWR);
    if (fds_[loadNum] > 0) {
        std::string url = "fd://" + std::to_string(fds_[loadNum]);
        soundIDs_[loadNum] = soundPoolParallel_->Load(url);
    } else {
        cout << "Url open failed, g_fileName " << fileName.c_str() << ", fd: " << fds_[loadNum] << endl;
    }
    EXPECT_GT(soundIDs_[loadNum], 0);
}

void SoundPoolUnitTest::loadFdParallel(std::string fileName, int32_t loadNum)
{
    fds_[loadNum] = open(fileName.c_str(), O_RDONLY);
    if (fds_[loadNum] < 0) {
        cout << "Fd open failed, g_fileName " << fileName.c_str() << ", Fd: " << fds_[loadNum] << endl;
    }
    size_t filesize = soundPoolParallel_->GetFileSize(fileName);
    EXPECT_NE(filesize, 0);
    soundIDs_[loadNum] = soundPoolParallel_->Load(fds_[loadNum], 0, filesize);
    EXPECT_GT(soundIDs_[loadNum], 0);
}

/**
 * @tc.name: soundpool_function_001
 * @tc.desc: function test Load Url one more time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_001, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_001 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_001 after");
}

/**
 * @tc.name: soundpool_function_002
 * @tc.desc: function test Load Url with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_002, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_002 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    // test invalid path
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDWR);
    std::string url = "fd://" + std::to_string(fds_[loadNum_]);
    soundIDs_[loadNum_] = soundPool_->Load(url);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Url open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_002 after");
}

/**
 * @tc.name: soundpool_function_003
 * @tc.desc: function test Load Url when no callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_003, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_003 before");
    int maxStreams = 3;
    create(maxStreams);
    // test no callback to load
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_003 after");
}

/**
 * @tc.name: soundpool_function_004
 * @tc.desc: function test Load Url after play
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_004, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_004 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        soundPool_->Play(soundIDs_[loadNum_], playParameters);
        sleep(waitTime1);
        loadNum_++;
        loadUrl(g_fileName[loadNum_], loadNum_);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_004 after");
}

/**
 * @tc.name: soundpool_function_005
 * @tc.desc: function test Load Fd one more time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_005, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_005 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadFd(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[1], loadNum_);
    loadNum_++;
    loadFd(g_fileName[1], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_005 after");
}

/**
 * @tc.name: soundpool_function_006
 * @tc.desc: function test Load Fd with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_006, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_006 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDONLY);
    size_t filesize = soundPool_->GetFileSize(fileName);
    EXPECT_EQ(filesize, 0);
    soundIDs_[loadNum_] = soundPool_->Load(fds_[loadNum_], 0, filesize);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Fd open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_006 after");
}

/**
 * @tc.name: soundpool_function_007
 * @tc.desc: function test Load Fd when no callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_007, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_007 before");
    int maxStreams = 3;
    create(maxStreams);
    // test no callback to load
    loadFd(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_007 after");
}

/**
 * @tc.name: soundpool_function_008
 * @tc.desc: function test Load Fd after paly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_008, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_008 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadFd(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        soundPool_->Play(soundIDs_[loadNum_], playParameters);
        sleep(waitTime1);
        loadNum_++;
        loadFd(g_fileName[loadNum_], loadNum_);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_008 after");
}

/**
 * @tc.name: soundpool_function_009
 * @tc.desc: function test UnLoad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_009, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_009 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);

    ASSERT_TRUE(cb->WaitLoadedSoundNum(4));
    cb->ResetHaveLoadedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPool_->Unload(soundIDs_[0]));
    EXPECT_EQ(MSERR_OK, soundPool_->Unload(soundIDs_[1]));
    EXPECT_EQ(MSERR_OK, soundPool_->Unload(soundIDs_[2]));
    EXPECT_EQ(MSERR_OK, soundPool_->Unload(soundIDs_[3]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_009 after");
}

/**
 * @tc.name: soundpool_function_010
 * @tc.desc: function test UnLoad with error path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_010, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_010 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    std::string fileName = "/data/test/test_05.mp3";
    fds_[loadNum_] = open(fileName.c_str(), O_RDWR);
    std::string url = "fd://" + std::to_string(fds_[loadNum_]);
    soundIDs_[loadNum_] = soundPool_->Load(url);
    if (fds_[loadNum_] == -1) {
        cout << "Url open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    loadNum_++;
    fds_[loadNum_] = open(fileName.c_str(), O_RDONLY);
    size_t filesize = soundPool_->GetFileSize(fileName);
    EXPECT_EQ(filesize, 0);
    soundIDs_[loadNum_] = soundPool_->Load(fds_[loadNum_], 0, filesize);
    sleep(waitTime3);
    if (fds_[loadNum_] == -1) {
        cout << "Fd open a invalid path: " << fileName.c_str() << endl;
    }
    EXPECT_EQ(soundIDs_[loadNum_], -1);
    // test UnLoad a invalid-path return soundId
    int32_t unload = soundPool_->Unload(soundIDs_[0]);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    unload = soundPool_->Unload(soundIDs_[1]);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_010 after");
}

/**
 * @tc.name: soundpool_function_011
 * @tc.desc: function test UnLoad with -1/5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_011, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_011 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    // test unload -1
    int32_t unload = soundPool_->Unload(-1);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    // test unload 5
    unload = soundPool_->Unload(5);
    EXPECT_EQ(MSERR_NO_MEMORY, unload);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_011 after");
}

/**
 * @tc.name: soundpool_function_012
 * @tc.desc: function test Play with undefault playParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_012, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_012 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);

    loadUrl(g_fileName[loadNum_], loadNum_);
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
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_012 after");
}

/**
 * @tc.name: soundpool_function_013
 * @tc.desc: function test Play with default playParameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_013, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_013 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_013 after");
}

/**
 * @tc.name: soundpool_function_014
 * @tc.desc: function test Play with error soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_014, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_014 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(5, playParameters);
    cout << "soundId 5 play, result: " << streamIDs_[playNum_] << endl;
    EXPECT_EQ(streamIDs_[playNum_], -1);
    sleep(waitTime1);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_014 after");
}

/**
 * @tc.name: soundpool_function_015
 * @tc.desc: function test Play with not load number -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_015, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_015 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(-1, playParameters);
    cout << "soundId -1 play, result: " << streamIDs_[playNum_] << endl;
    EXPECT_EQ(streamIDs_[playNum_], -1);
    sleep(waitTime1);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_015 after");
}

/**
 * @tc.name: soundpool_function_016
 * @tc.desc: function test Play with different soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_016, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_016 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    sleep(waitTime1);
    playNum_++;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_016 after");
}

/**
 * @tc.name: soundpool_function_017
 * @tc.desc: function test Stop with same streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_017, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_017 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    if (streamIDs_[playNum_] > 0) {
        int32_t stopResult = soundPool_->Stop(streamIDs_[playNum_]);
        EXPECT_EQ(MSERR_OK, stopResult);
        sleep(waitTime1);
        int32_t stopResult1 = soundPool_->Stop(streamIDs_[playNum_]);
        EXPECT_EQ(MSERR_OK, stopResult1);
    }
    MEDIA_LOGI("soundpool_unit_test soundpool_function_017 after");
}

/**
 * @tc.name: soundpool_function_018
 * @tc.desc: function test Stop with different streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_018, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_018 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    if (streamIDs_[0] > 0) {
        EXPECT_EQ(MSERR_OK, soundPool_->Stop(streamIDs_[0]));
    }
    if (streamIDs_[1] > 0) {
        EXPECT_EQ(MSERR_OK, soundPool_->Stop(streamIDs_[1]));
    }
    MEDIA_LOGI("soundpool_unit_test soundpool_function_018 after");
}

/**
 * @tc.name: soundpool_function_019
 * @tc.desc: function test not Stop all streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_019, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_019 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadFd(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(3));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPool_->Stop(streamIDs_[0]));
    EXPECT_EQ(MSERR_OK, soundPool_->Stop(streamIDs_[2]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_019 after");
}

/**
 * @tc.name: soundpool_function_020
 * @tc.desc: function test Stop with -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_020, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_020 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    int32_t stopResult = soundPool_->Stop(-1);
    EXPECT_EQ(MSERR_INVALID_OPERATION, stopResult);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_020 after");
}

/**
 * @tc.name: soundpool_function_021
 * @tc.desc: function test SetLoop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_021, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_021 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    EXPECT_EQ(MSERR_OK, soundPool_->Unload(soundIDs_[loadNum_]));
    MEDIA_LOGI("soundpool_unit_test soundpool_function_021 after");
}

/**
 * @tc.name: soundpool_function_022
 * @tc.desc: function test SetLoop 3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_022, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_022 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = 3;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_022 after");
}

/**
 * @tc.name: soundpool_function_023
 * @tc.desc: function test SetLoop -2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_023, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_023 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -2;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_023 after");
}

/**
 * @tc.name: soundpool_function_024
 * @tc.desc: function test SetLoop -1, streamID is -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_024, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_024 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = 0;
    int32_t loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(-1, loop);
        EXPECT_EQ(MSERR_INVALID_OPERATION, setPool);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_024 after");
}

/**
 * @tc.name: soundpool_function_025
 * @tc.desc: function test SetLoop 2 with different streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_025, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_025 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    int32_t loop = 2;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool1 = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_025 after");
}

/**
 * @tc.name: soundpool_function_026
 * @tc.desc: function test SetLoop different loop with different streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_026, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_026 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    int32_t loop = 2;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool = soundPool_->SetLoop(streamIDs_[playNum_], loop);
        EXPECT_EQ(MSERR_OK, setPool);
        sleep(waitTime3);
        playNum_++;
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setPool1 = soundPool_->SetLoop(streamIDs_[playNum_], -1);
        EXPECT_EQ(MSERR_OK, setPool1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_026 after");
}

/**
 * @tc.name: soundpool_function_027
 * @tc.desc: function test SetRate with different rate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_027, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_027 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setRateResult = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, setRateResult);
        sleep(waitTime3);
        int32_t setRateResult1 = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_HALF);
        EXPECT_EQ(MSERR_OK, setRateResult1);
        sleep(waitTime3);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }

    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_027 after");
}

/**
 * @tc.name: soundpool_function_028
 * @tc.desc: function test SetRate with different rate and streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_028, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_028 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setRateResult = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, setRateResult);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setRateResult = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_HALF);
        EXPECT_EQ(MSERR_OK, setRateResult);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_028 after");
}

/**
 * @tc.name: soundpool_function_029
 * @tc.desc: function test SetRate with different streamID and same rate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_029, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_029 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setRateResult = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, setRateResult);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setRateResult = soundPool_->SetRate(streamIDs_[playNum_], AudioRendererRate::RENDER_RATE_DOUBLE);
        EXPECT_EQ(MSERR_OK, setRateResult);
        sleep(waitTime3);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_029 after");
}

/**
 * @tc.name: soundpool_function_030
 * @tc.desc: function test SetVolume 0.5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_030, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_030 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = 0.5;
    float rightVolume = 0.5;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPool_->SetVolume(streamIDs_[playNum_], leftVolume, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_030 after");
}

/**
 * @tc.name: soundpool_function_031
 * @tc.desc: function test SetVolume deifferent leftVolume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_031, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_031 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = 0.1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPool_->SetVolume(streamIDs_[playNum_], leftVolume, 0.0);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime3);
        int32_t setVol1 = soundPool_->SetVolume(streamIDs_[playNum_], 1.0, 0.0);
        EXPECT_EQ(MSERR_OK, setVol1);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_031 after");
}

/**
 * @tc.name: soundpool_function_032
 * @tc.desc: function test SetVolume leftVolume -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_032, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_032 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float leftVolume = -1;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPool_->SetVolume(streamIDs_[playNum_], leftVolume, 0.0);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_032 after");
}

/**
 * @tc.name: soundpool_function_033
 * @tc.desc: function test SetVolume rightVolume 2.0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_033, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_033 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(1));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    float rightVolume = 2.0;
    if (soundIDs_[loadNum_] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[loadNum_], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        int32_t setVol = soundPool_->SetVolume(streamIDs_[playNum_], 0.0, rightVolume);
        EXPECT_EQ(MSERR_OK, setVol);
        sleep(waitTime1);
    } else {
        cout << "Get soundId failed, please try to get soundId: " << soundIDs_[loadNum_] << endl;
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_033 after");
}

/**
 * @tc.name: soundpool_function_034
 * @tc.desc: function test SetPriority 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_034, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_034 before");
    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    ASSERT_TRUE(ret == 0);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.loop = -1;
    int32_t priority  = 1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
        int32_t setPriority = soundPool_->SetPriority(streamIDs_[playNum_], priority);
        EXPECT_EQ(MSERR_OK, setPriority);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_034 after");
}


/**
 * @tc.name: soundpool_function_035
 * @tc.desc: function test SetPriority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_035, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_035 before");
    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    ASSERT_TRUE(cb != nullptr);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[loadNum_], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[loadNum_], loadNum_);
    sleep(waitTime3);
    ASSERT_TRUE(cb->WaitLoadedSoundNum(2));
    cb->ResetHaveLoadedSoundNum();
    struct PlayParams playParameters;
    playParameters.priority = 1;
    playParameters.loop = -1;
    int32_t priority  = -1;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime3);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[1], 0);
        sleep(waitTime3);
    }
    int32_t setPriority = soundPool_->SetPriority(streamIDs_[0], priority);
    sleep(waitTime1);
    EXPECT_EQ(MSERR_OK, setPriority);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_035 after");
}

/**
 * @tc.name: soundpool_function_036
 * @tc.desc: function test Priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_036, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_036 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[0], loadNum_);
    sleep(waitTime3);
    struct PlayParams playParameters;
    playParameters.priority = 3;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    playParameters.priority = 5;
    if (soundIDs_[3] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[3], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    sleep(15);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_036 after");
}

/**
 * @tc.name: soundpool_function_037
 * @tc.desc: function test Priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_037, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_037 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    int32_t ret = soundPool_->SetSoundPoolCallback(cb);
    if (ret != 0) {
        cout << "set callback failed" << endl;
    }
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[1], loadNum_);
    loadNum_++;
    loadUrl(g_fileName[0], loadNum_);
    sleep(waitTime3);
    struct PlayParams playParameters;
    playParameters.priority = 3;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[1] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    if (soundIDs_[2] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[2], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    playNum_++;
    playParameters.priority = 1;
    if (soundIDs_[3] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[3], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime2);
    }
    sleep(15);
    cb->ResetHavePlayedSoundNum();
    MEDIA_LOGI("soundpool_unit_test soundpool_function_037 after");
}


/**
 * @tc.name: soundpool_function_038
 * @tc.desc: function test MaxStreams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_038, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_038 before");

    int maxStreams = 3;
    create(maxStreams);
    maxStreams = -1;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_FALSE(soundPool_->CreateSoundPool(maxStreams, audioRenderInfo));
    maxStreams = 256;
    EXPECT_TRUE(soundPool_->CreateSoundPool(maxStreams, audioRenderInfo));

    MEDIA_LOGI("soundpool_unit_test soundpool_function_038 after");
}

/**
 * @tc.name: soundpool_function_039
 * @tc.desc: function test AudioStream DoPlay fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_039, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_039 before");

    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[1], loadNum_);
    sleep(5);
    struct PlayParams playParameters;
    if (soundIDs_[0] > 0) {
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
        streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
        EXPECT_GT(streamIDs_[playNum_], 0);
        sleep(waitTime1);
    }
    cb->ResetHavePlayedSoundNum();

    MEDIA_LOGI("soundpool_unit_test soundpool_function_039 after");
}

/**
 * @tc.name: soundpool_function_040
 * @tc.desc: function test play Priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_040, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_040 before");

    int maxStreams = 4;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[2], loadNum_++);
    loadUrl(g_fileName[1], loadNum_++);
    loadUrl(g_fileName[4], loadNum_++);
    loadUrl(g_fileName[5], loadNum_++);
    sleep(5);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPool_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[3], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[3], 4);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime10);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_040 after");
}

/**
 * @tc.name: soundpool_function_041
 * @tc.desc: function test willplay Priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_041, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_041 before");

    int maxStreams = 1;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[2], loadNum_++);
    loadUrl(g_fileName[1], loadNum_++);
    loadUrl(g_fileName[4], loadNum_++);
    loadUrl(g_fileName[5], loadNum_++);
    sleep(5);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t setPriority = soundPool_->SetPriority(streamIDs_[0], 1);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[1], 2);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[2], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[2], 3);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime1);

    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[3], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    setPriority = soundPool_->SetPriority(streamIDs_[3], 4);
    EXPECT_EQ(MSERR_OK, setPriority);
    playNum_++;
    sleep(waitTime30);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_041 after");
}


/**
 * @tc.name: soundpool_function_042
 * @tc.desc: function test playFinished with streamId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_042, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_042 before");
    int maxStreams = 3;
    create(maxStreams);
    std::shared_ptr<SoundPoolCallbackTest> cb = std::make_shared<SoundPoolCallbackTest>(soundPool_);
    soundPool_->SetSoundPoolCallback(cb);
    loadUrl(g_fileName[4], loadNum_++);
    loadUrl(g_fileName[5], loadNum_++);
    sleep(waitTime3);
    struct PlayParams playParameters;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[0], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    sleep(waitTime1);
    playNum_++;
    streamIDs_[playNum_] = soundPool_->Play(soundIDs_[1], playParameters);
    EXPECT_GT(streamIDs_[playNum_], 0);
    int32_t totalNum = playNum_ + 1;
    int32_t matchNum = 0;
    sleep(waitTime10);

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
    MEDIA_LOGI("soundpool_unit_test soundpool_function_042 after");
}

/**
 * @tc.name: soundpool_function_043
 * @tc.desc: function test soundpool multi instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_043, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_043 before");
    int maxStreams = 3;
    create(maxStreams);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;

    std::shared_ptr<SoundPoolMock> soundPool1 = std::make_shared<SoundPoolMock>();
    std::shared_ptr<SoundPoolMock> soundPool2 = std::make_shared<SoundPoolMock>();
    EXPECT_TRUE(soundPool1->CreateSoundPool(maxStreams, audioRenderInfo));
    EXPECT_TRUE(soundPool2->CreateSoundPool(maxStreams, audioRenderInfo));
    std::shared_ptr<SoundPoolCallbackTest> cb1 = std::make_shared<SoundPoolCallbackTest>(soundPool1);
    soundPool1->SetSoundPoolCallback(cb1);
    std::shared_ptr<SoundPoolCallbackTest> cb2 = std::make_shared<SoundPoolCallbackTest>(soundPool2);
    soundPool2->SetSoundPoolCallback(cb2);

    functionTest043(soundPool1, soundPool2, cb1, cb2);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_043 after");
}

void SoundPoolUnitTest::functionTest043(std::shared_ptr<SoundPoolMock> soundPool1,
    std::shared_ptr<SoundPoolMock> soundPool2, std::shared_ptr<SoundPoolCallbackTest> cb1,
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
    sleep(waitTime3);

    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num3]));

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
 * @tc.name: soundpool_function_094
 * @tc.desc: function test soundpool multi instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_094, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_094 before");
    int maxStreams = 3;
    create(maxStreams);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = STREAM_USAGE_MEDIA;
    audioRenderInfo.rendererFlags = 0;

    std::shared_ptr<SoundPoolMock> soundPool1 = std::make_shared<SoundPoolMock>();
    std::shared_ptr<SoundPoolMock> soundPool2 = std::make_shared<SoundPoolMock>();
    EXPECT_TRUE(soundPool1->CreateSoundPool(maxStreams, audioRenderInfo));
    EXPECT_TRUE(soundPool2->CreateSoundPool(maxStreams, audioRenderInfo));
    std::shared_ptr<SoundPoolCallbackTest> cb1 = std::make_shared<SoundPoolCallbackTest>(soundPool1);
    soundPool1->SetSoundPoolCallback(cb1);
    std::shared_ptr<SoundPoolCallbackTest> cb2 = std::make_shared<SoundPoolCallbackTest>(soundPool2);
    soundPool2->SetSoundPoolCallback(cb2);

    functionTest094(soundPool1, soundPool2, cb1, cb2);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_094 after");
}

void SoundPoolUnitTest::functionTest094(std::shared_ptr<SoundPoolMock> soundPool1,
    std::shared_ptr<SoundPoolMock> soundPool2, std::shared_ptr<SoundPoolCallbackTest> cb1,
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
    sleep(waitTime3);

    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num3]));

    EXPECT_EQ(soundNum, cb1->GetHaveLoadedSoundNum());
    EXPECT_EQ(soundNum, cb1->GetHavePlayedSoundNum());
    EXPECT_EQ(soundNum, cb2->GetHaveLoadedSoundNum());
    EXPECT_EQ(soundNum, cb2->GetHavePlayedSoundNum());

    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num3]));

    EXPECT_EQ(MSERR_OK, soundPool1->Release());
    EXPECT_EQ(MSERR_OK, soundPool2->Release());
}

/**
 * @tc.name: soundpool_function_095
 * @tc.desc: function test soundpool multi instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_095, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_095 before");
    int maxStreams = 3;
    create(maxStreams);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.streamUsage = STREAM_USAGE_MOVIE;
    audioRenderInfo.rendererFlags = 0;

    std::shared_ptr<SoundPoolMock> soundPool1 = std::make_shared<SoundPoolMock>();
    std::shared_ptr<SoundPoolMock> soundPool2 = std::make_shared<SoundPoolMock>();
    EXPECT_TRUE(soundPool1->CreateSoundPool(maxStreams, audioRenderInfo));
    EXPECT_TRUE(soundPool2->CreateSoundPool(maxStreams, audioRenderInfo));
    std::shared_ptr<SoundPoolCallbackTest> cb1 = std::make_shared<SoundPoolCallbackTest>(soundPool1);
    soundPool1->SetSoundPoolCallback(cb1);
    std::shared_ptr<SoundPoolCallbackTest> cb2 = std::make_shared<SoundPoolCallbackTest>(soundPool2);
    soundPool2->SetSoundPoolCallback(cb2);

    functionTest095(soundPool1, soundPool2, cb1, cb2);

    MEDIA_LOGI("soundpool_unit_test soundpool_function_095 after");
}

void SoundPoolUnitTest::functionTest095(std::shared_ptr<SoundPoolMock> soundPool1,
    std::shared_ptr<SoundPoolMock> soundPool2, std::shared_ptr<SoundPoolCallbackTest> cb1,
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
    sleep(waitTime3);

    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Stop(streamIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Stop(streamIDs_[num3]));

    EXPECT_EQ(soundNum, cb1->GetHaveLoadedSoundNum());
    EXPECT_EQ(soundNum, cb1->GetHavePlayedSoundNum());
    EXPECT_EQ(soundNum, cb2->GetHaveLoadedSoundNum());
    EXPECT_EQ(soundNum, cb2->GetHavePlayedSoundNum());

    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num0]));
    EXPECT_EQ(MSERR_OK, soundPool1->Unload(soundIDs_[num1]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num2]));
    EXPECT_EQ(MSERR_OK, soundPool2->Unload(soundIDs_[num3]));

    EXPECT_EQ(MSERR_OK, soundPool1->Release());
    EXPECT_EQ(MSERR_OK, soundPool2->Release());
}

/**
 * @tc.name: soundpool_function_96
 * @tc.desc: function test SetSoundPoolFrameWriteCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolUnitTest, soundpool_function_096, TestSize.Level2)
{
    MEDIA_LOGI("soundpool_unit_test soundpool_function_044 before");
    create(MAX_STREAMS);
    std::shared_ptr<SoundPoolFrameWriteCallbackTest> cb = std::make_shared<SoundPoolFrameWriteCallbackTest>();
    int32_t ret = soundPool_->soundPool_->SetSoundPoolFrameWriteCallback(cb);
    EXPECT_EQ(MSERR_OK, ret);
    MEDIA_LOGI("soundpool_unit_test soundpool_function_044 after");
}

} // namespace Media
} // namespace OHOS