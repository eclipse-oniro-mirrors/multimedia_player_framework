/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MD "/data/test/ChineseColor_H264_AAC_480p_15fps.mp4"
#define ISNETWORK_SUBTITLE_URL "http://example.com/subtitle.srt"
#define LOCAL_SUBTITLE_PATH "/data/test/utf8.srt"
#define WAIT_TIMEOUT_SHORT 2000
#define WAIT_TIMEOUT_LONG 5000

#include <condition_variable>
#include <mutex>
#include <thread>
#include <fcntl.h>
#include <fstream>
#include "gtest/gtest.h"
#include "avplayer.h"
#include "avplayer_base.h"
#include "avplayer_unittest.h"
#include "native_player_magic.h"
#include "native_mfmagic.h"
#include "media_errors.h"
#include "media_log.h"
#include "avsei_message_impl.h"
#include "avmedia_source.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerUnitTest"};
}

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

static const string TEST_FILE_PATH = "/data/test/media/test_264_B_Gop25_4sec_cover.mp4";

void AVPlayerUnitTest::SetUpTestCase(void) {}

void AVPlayerUnitTest::TearDownTestCase(void) {}

void AVPlayerUnitTest::SetUp(void) {}

void AVPlayerUnitTest::TearDown(void) {}

static int32_t AVSourceReadAt(OH_AVBuffer *data, int32_t length, int64_t pos)
{
    if (data == nullptr) {
        printf("AVSourceReadAt : data is nullptr!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    std::ifstream infile(TEST_FILE_PATH, std::ofstream::binary);
    if (!infile.is_open()) {
        printf("AVSourceReadAt : open file failed! file:%s\n", TEST_FILE_PATH.c_str());
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;  // 打开文件失败
    }

    infile.seekg(0, std::ios::end);
    int64_t fileSize = infile.tellg();
    if (pos >= fileSize) {
        printf("AVSourceReadAt : pos over or equals file size!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_EOF;  // pos已经是文件末尾位置，无法读取
    }

    if (pos + length > fileSize) {
        length = fileSize - pos;    // pos+length长度超过文件大小时，读取从pos到文件末尾的数据
    }

    infile.seekg(pos, std::ios::beg);
    if (length <= 0) {
        printf("AVSourceReadAt : raed length less than zero!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }
    char* buffer = new char[length];
    infile.read(buffer, length);
    infile.close();

    errno_t result = memcpy_s(reinterpret_cast<char *>(OH_AVBuffer_GetAddr(data)),
        OH_AVBuffer_GetCapacity(data), buffer, length);
    delete[] buffer;
    if (result != 0) {
        printf("memcpy_s failed!");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    return length;
}

int64_t GetFileSize(const string &fileName)
{
    int64_t fileSize = 0;
    if (!fileName.empty()) {
        struct stat fileStatus {};
        if (stat(fileName.c_str(), &fileStatus) == 0) {
            fileSize = static_cast<int64_t>(fileStatus.st_size);
        }
    }
    return fileSize;
}

/**
 * @tc.name: OH_AVPlayer_SetMediaSourceTest
 * @tc.desc: Verify that AVPlayer can set MediaSource successfully and parameters cannot be nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaSourceTest, TestSize.Level1)
{
    const char* url = "http://example.com/video.mp4";
    OH_AVHttpHeader* header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediaSource, nullptr);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(nullptr, mediaSource), AV_ERR_INVALID_VAL);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, nullptr), AV_ERR_INVALID_VAL);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaSourceTest002
 * @tc.desc: Verify that AVPlayer cannot set MediaSource successfully when player state isnot idle.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaSourceTest002, TestSize.Level1)
{
    const char* url = "http://example.com/video.mp4";
    OH_AVHttpHeader* header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediaSource, nullptr);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    player->state_ = PLAYER_PAUSED;
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_INVALID_VAL);
    player->state_ = PLAYER_IDLE;
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaSourceTest003
 * @tc.desc: Verify that AVPlayer can set MediaSource successfully when source create by fd.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaSourceTest003, TestSize.Level1)
{
    int32_t fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    int64_t offset = 999999;
    int64_t size = GetFileSize(TEST_FILE_PATH);
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithFd(fd, offset, size);
    ASSERT_NE(mediaSource, nullptr);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaSourceTest004
 * @tc.desc: Verify that AVPlayer can set MediaSource successfully when source create by data source.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaSourceTest004, TestSize.Level1)
{
    int64_t size = GetFileSize(TEST_FILE_PATH);
    OH_AVDataSource dataSource = {size, AVSourceReadAt};
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithDataSource(&dataSource);
    ASSERT_NE(mediaSource, nullptr);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaSourceTest005
 * @tc.desc: Verify that AVPlayer can set MediaSource successfully when source create by url.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaSourceTest005, TestSize.Level1)
{
    const char* url = "http://example.com/video.mp4";
    OH_AVHttpHeader* header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediaSource, nullptr);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    ASSERT_EQ(OH_AVPlayer_SetMediaSource(player, mediaSource), AV_ERR_OK);
}

void OnSeiMessageReceivedCallback(OH_AVPlayer *Player, OH_AVSeiMessageArray *message,
    int32_t playbackPosition, void *userData)
{
    MEDIA_LOGI("OnSeiMessageReceivedCallback received sei message");
}

/**
 * @tc.name: OH_AVPlayer_SetSeiReceivedCallback_001
 * @tc.desc: Verify that AVPlayer set sei message received callback successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetSeiReceivedCallback_001, TestSize.Level1)
{
    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);

    std::vector<int> payloadTypes = { 5, 6 };
    int32_t userData = 0;
    uint32_t typeNum = static_cast<uint32_t>(payloadTypes.size());
    int ret = OH_AVPlayer_SetSeiReceivedCallback(player, payloadTypes.data(), typeNum,
        OnSeiMessageReceivedCallback, reinterpret_cast<void *>(&userData));
    ASSERT_EQ(ret, MSERR_OK);

    ret = OH_AVPlayer_SetSeiReceivedCallback(player, payloadTypes.data(), typeNum,
        nullptr, reinterpret_cast<void *>(&userData));
    ASSERT_EQ(ret, MSERR_OK);

    ret = OH_AVPlayer_SetSeiReceivedCallback(player, payloadTypes.data(), typeNum,
        OnSeiMessageReceivedCallback, nullptr);
    ASSERT_EQ(ret, MSERR_OK);

    ret = OH_AVPlayer_Release(player);
    ASSERT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetSeiReceivedCallback_002
 * @tc.desc: Verify that AVPlayer set sei message received callback by invalid parameter.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetSeiReceivedCallback_002, TestSize.Level2)
{
    std::vector<int> payloadTypes = { 5, 6 };
    uint32_t typeNum = static_cast<uint32_t>(payloadTypes.size());
    int ret = OH_AVPlayer_SetSeiReceivedCallback(nullptr, payloadTypes.data(), typeNum,
        OnSeiMessageReceivedCallback, nullptr);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);

    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);

    ret = OH_AVPlayer_SetSeiReceivedCallback(player, nullptr, typeNum,
        OnSeiMessageReceivedCallback, nullptr);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);

    ret = OH_AVPlayer_Release(player);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: OH_AVSeiMessage_GetSEICount_001
 * @tc.desc: Verify get sei count successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVSeiMessage_GetSEICount_001, TestSize.Level1)
{
    SeiMessageArray *seiMessage = new (std::nothrow) SeiMessageArray({
        Format(), Format(), Format()
    });
    ASSERT_NE(seiMessage, nullptr);

    uint32_t ret = OH_AVSeiMessage_GetSeiCount(seiMessage);
    ASSERT_EQ(ret, 3);
    delete seiMessage;
}

/**
 * @tc.name: OH_AVSeiMessage_GetSEICount_002
 * @tc.desc: Verify get sei count by invalid parameter.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVSeiMessage_GetSEICount_002, TestSize.Level2)
{
    uint32_t ret = OH_AVSeiMessage_GetSeiCount(nullptr);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: OH_AVSeiMessage_GetSEI_001
 * @tc.desc: Verify get sei successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVSeiMessage_GetSEI_001, TestSize.Level1)
{
    SeiMessageArray *seiMessage = new (std::nothrow) SeiMessageArray({
        Format(), Format(), Format()
    });
    ASSERT_NE(seiMessage, nullptr);

    OH_AVFormat *format = OH_AVSeiMessage_GetSei(seiMessage, 0);
    ASSERT_NE(format, nullptr);
    delete seiMessage;
    OH_AVFormat_Destroy(format);
}

/**
 * @tc.name: OH_AVSeiMessage_GetSEI_002
 * @tc.desc: Verify get sei by invalid parameter.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVSeiMessage_GetSEI_002, TestSize.Level2)
{
    OH_AVFormat *format = OH_AVSeiMessage_GetSei(nullptr, 0);
    ASSERT_EQ(format, nullptr);

    SeiMessageArray *seiMessage = new (std::nothrow) SeiMessageArray({
        Format(), Format(), Format()
    });
    ASSERT_NE(seiMessage, nullptr);

    format = OH_AVSeiMessage_GetSei(seiMessage, 6);
    ASSERT_EQ(format, nullptr);
    delete seiMessage;
}

/**
 * @tc.name: OH_AVPlayer_SetAmplitudeUpdateCallback_0100
 * @tc.desc: Set amplitude update callback on a valid player.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetAmplitudeUpdateCallback_0100, TestSize.Level2)
{
    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(nullptr, player);

    auto amplitudeCallback = [](OH_AVPlayer* player, double *amp, uint32_t count, void* userData) {
        ASSERT_NE(nullptr, player);
        ASSERT_NE(nullptr, amp);
        ASSERT_GT(count, 0);

        if (userData != nullptr) {
            int* callbackCount = static_cast<int*>(userData);
            (*callbackCount)++;
        }
    };

    int callbackCount = 0;
    OH_AVErrCode ret = OH_AVPlayer_SetAmplitudeUpdateCallback(player, amplitudeCallback, &callbackCount);
    EXPECT_EQ(AV_ERR_OK, ret);

    ret = OH_AVPlayer_Release(player);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetAmplitudeUpdateCallback_0200
 * @tc.desc: Call SetAmplitudeUpdateCallback with a null player.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetAmplitudeUpdateCallback_0200, TestSize.Level2)
{
    OH_AVErrCode ret = OH_AVPlayer_SetAmplitudeUpdateCallback(nullptr, nullptr, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetAmplitudeUpdateCallback_0300
 * @tc.desc: Register then unregister amplitude update callback on a valid player.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetAmplitudeUpdateCallback_0300, TestSize.Level2)
{
    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(nullptr, player);

    auto amplitudeCallback = [](OH_AVPlayer* player, double *amp, uint32_t count, void* userData) {
    };

    OH_AVErrCode ret = OH_AVPlayer_SetAmplitudeUpdateCallback(player, amplitudeCallback, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);

    ret = OH_AVPlayer_SetAmplitudeUpdateCallback(player, nullptr, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);

    ret = OH_AVPlayer_Release(player);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetAmplitudeUpdateCallback_0400
 * @tc.desc: Set amplitude update callback with valid player and null userData.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetAmplitudeUpdateCallback_0400, TestSize.Level2)
{
    OH_AVPlayer* player = nullptr;
    player = OH_AVPlayer_Create();
    ASSERT_NE(nullptr, player);

    auto amplitudeCallback = [](OH_AVPlayer* player, double *amp, uint32_t count, void* userData) {
        ASSERT_NE(nullptr, player);
        ASSERT_NE(nullptr, amp);
        EXPECT_GE(count, 0);
    };

    OH_AVErrCode ret = OH_AVPlayer_SetAmplitudeUpdateCallback(player, amplitudeCallback, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);

    ret = OH_AVPlayer_Release(player);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetTargetVideoWindowSizeTest
 * @tc.desc: Verify that setting the target video window size works correctly.
 *           Checks invalid player pointer, invalid player state, and valid state behavior.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetTargetVideoWindowSizeTest, TestSize.Level1)
{
    OH_AVPlayer* player = nullptr;
    int32_t width = 1920;
    int32_t height = 1080;
    EXPECT_EQ(OH_AVPlayer_SetTargetVideoWindowSize(player, width, height), AV_ERR_INVALID_VAL);

    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto re = OH_AVPlayer_SetFDSource(player, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    player->state_ = PLAYER_INITIALIZED;
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetSuperResolutionEnable(strategy, true), AV_ERR_OK);
    ASSERT_EQ(OH_AVPlayer_SetPlaybackStrategy(player, strategy), AV_ERR_OK);

    player->state_ = PLAYER_STATE_ERROR;
    EXPECT_EQ(OH_AVPlayer_SetTargetVideoWindowSize(player, width, height), AV_ERR_OPERATE_NOT_PERMIT);

    player->state_ = PLAYER_STOPPED;
    EXPECT_EQ(OH_AVPlayer_SetTargetVideoWindowSize(player, width, height), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetVideoSuperResolutionEnableTest
 * @tc.desc: Verify that enabling or disabling super resolution works correctly.
 *           Checks invalid player pointer, invalid player state, and valid state behavior.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetVideoSuperResolutionEnableTest, TestSize.Level1)
{
    OH_AVPlayer* player = nullptr;
    EXPECT_EQ(OH_AVPlayer_SetVideoSuperResolutionEnable(player, true), AV_ERR_INVALID_VAL);

    player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto re = OH_AVPlayer_SetFDSource(player, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    player->state_ = PLAYER_INITIALIZED;
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetSuperResolutionEnable(strategy, true), AV_ERR_OK);
    ASSERT_EQ(OH_AVPlayer_SetPlaybackStrategy(player, strategy), AV_ERR_OK);

    player->state_ = PLAYER_STATE_ERROR;
    EXPECT_EQ(OH_AVPlayer_SetVideoSuperResolutionEnable(player, true), AV_ERR_OPERATE_NOT_PERMIT);

    player->state_ = PLAYER_STOPPED;
    EXPECT_EQ(OH_AVPlayer_SetVideoSuperResolutionEnable(player, true), AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlaybackStrategy_CreateTest
 * @tc.desc: Verify that AVPlaybackStrategy can be created successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlaybackStrategy_CreateTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);
    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlaybackStrategy_DestroyTest
 * @tc.desc: Verify that AVPlaybackStrategy can be destroyed and handles null correctly.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlaybackStrategy_DestroyTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
    err = OH_AVPlaybackStrategy_Destroy(nullptr);
    ASSERT_EQ(err, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackStrategyTest001
 * @tc.desc: Verify setting playback strategy with valid and invalid inputs.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetPlaybackStrategyTest001, TestSize.Level1)
{
    OH_AVPlayer* player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto re = OH_AVPlayer_SetFDSource(player, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    player->state_ = PLAYER_INITIALIZED;
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);
    double value = 0;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(strategy, value), AV_ERR_OK);
    double threshold = -1;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(strategy, threshold), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlayer_SetPlaybackStrategy(player, strategy);
    ASSERT_EQ(err, AV_ERR_OK);
    err = OH_AVPlayer_SetPlaybackStrategy(nullptr, strategy);
    ASSERT_EQ(err, AV_ERR_INVALID_VAL);
    err = OH_AVPlayer_SetPlaybackStrategy(player, nullptr);
    ASSERT_EQ(err, AV_ERR_INVALID_VAL);
    err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackStrategyTest002
 * @tc.desc: Verify SetPlaybackStrategy returns AV_ERR_OPERATE_NOT_PERMIT when state is not INITIALIZED or STOPPED.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetPlaybackStrategyTest002, TestSize.Level1)
{
    OH_AVPlayer* player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto re = OH_AVPlayer_SetFDSource(player, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    player->state_ = PLAYER_PAUSED;
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);
    double value = 0;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(strategy, value), AV_ERR_OK);
    double threshold = -1;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(strategy, threshold), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlayer_SetPlaybackStrategy(player, strategy);
    ASSERT_EQ(err, AV_ERR_OPERATE_NOT_PERMIT);

    err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackStrategyTest003
 * @tc.desc: Verify SetPlaybackStrategy returns AV_ERR_INVALID_VAL when playback strategy parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetPlaybackStrategyTest003, TestSize.Level1)
{
    OH_AVPlayer* player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto re = OH_AVPlayer_SetFDSource(player, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    player->state_ = PLAYER_INITIALIZED;
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    double value = -1;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(strategy, value), AV_ERR_OK);
    double threshold = -1;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(strategy, threshold), AV_ERR_OK);
    OH_AVErrCode err = OH_AVPlayer_SetPlaybackStrategy(player, strategy);
    ASSERT_EQ(err, AV_ERR_INVALID_VAL);

    value = 0;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(strategy, value), AV_ERR_OK);
    threshold = 0;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(strategy, threshold), AV_ERR_OK);
    err = OH_AVPlayer_SetPlaybackStrategy(player, strategy);
    ASSERT_EQ(err, AV_ERR_INVALID_VAL);

    err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredWidth_SetTest
 * @tc.desc: Verify setting preferred width.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredWidth_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    uint32_t width = 1920;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredWidth(nullptr, width), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredWidth(strategy, width), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredHeight_SetTest
 * @tc.desc: Verify setting preferred height.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredHeight_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    uint32_t height = 1080;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredHeight(nullptr, height), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredHeight(strategy, height), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredBufferDuration_SetTest
 * @tc.desc: Verify setting preferred buffer duration.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredBufferDuration_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    uint32_t duration = 5000;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDuration(nullptr, duration), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDuration(strategy, duration), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredBufferDurationForPlaying_SetTest
 * @tc.desc: Verify setting preferred buffer duration for playing.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredBufferDurationForPlaying_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    double value = 2.5;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(nullptr, value), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredBufferDurationForPlaying(strategy, value), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: ThresholdForAutoQuickPlay_SetTest
 * @tc.desc: Verify setting threshold for auto quick play.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, ThresholdForAutoQuickPlay_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    double threshold = 0.8;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(nullptr, threshold), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetThresholdForAutoQuickPlay(strategy, threshold), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredHdr_SetTest
 * @tc.desc: Verify setting preferred HDR flag.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredHdr_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredHdr(nullptr, true), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredHdr(strategy, true), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: ShowFirstFrameOnPrepare_SetTest
 * @tc.desc: Verify setting show-first-frame-on-prepare option.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, ShowFirstFrameOnPrepare_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    EXPECT_EQ(OH_AVPlaybackStrategy_SetShowFirstFrameOnPrepare(nullptr, true), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetShowFirstFrameOnPrepare(strategy, true), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: SuperResolution_SetTest
 * @tc.desc: Verify setting super resolution option.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, SuperResolution_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    EXPECT_EQ(OH_AVPlaybackStrategy_SetSuperResolutionEnable(nullptr, true), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetSuperResolutionEnable(strategy, true), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: MutedMediaType_SetTest
 * @tc.desc: Verify setting muted media type.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, MutedMediaType_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    OH_MediaType mediaType = OH_MediaType::MEDIA_TYPE_AUD;
    EXPECT_EQ(OH_AVPlaybackStrategy_SetMutedMediaType(nullptr, mediaType), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetMutedMediaType(strategy, mediaType), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredAudioLanguage_SetTest
 * @tc.desc: Verify setting preferred audio language.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredAudioLanguage_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    const char* lang = "en-US";
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredAudioLanguage(nullptr, lang), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredAudioLanguage(strategy, nullptr), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredAudioLanguage(strategy, lang), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: PreferredSubtitleLanguage_SetTest
 * @tc.desc: Verify setting preferred subtitle language.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, PreferredSubtitleLanguage_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    const char* lang = "zh-CN";
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredSubtitleLanguage(nullptr, lang), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredSubtitleLanguage(strategy, nullptr), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetPreferredSubtitleLanguage(strategy, lang), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

/**
 * @tc.name: KeepDecodingOnMute_SetTest
 * @tc.desc: Verify setting keep-decoding-on-mute flag.
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, KeepDecodingOnMute_SetTest, TestSize.Level1)
{
    OH_AVPlaybackStrategy* strategy = OH_AVPlaybackStrategy_Create();
    ASSERT_NE(strategy, nullptr);

    EXPECT_EQ(OH_AVPlaybackStrategy_SetKeepDecodingOnMute(nullptr, true), AV_ERR_INVALID_VAL);
    EXPECT_EQ(OH_AVPlaybackStrategy_SetKeepDecodingOnMute(strategy, true), AV_ERR_OK);

    OH_AVErrCode err = OH_AVPlaybackStrategy_Destroy(strategy);
    ASSERT_EQ(err, AV_ERR_OK);
}

void AVPlayerMp4UnitTest::SetUpTestCase(void) {}

void AVPlayerMp4UnitTest::TearDownTestCase(void) {}

void AVPlayerMp4UnitTest::SetUp(void)
{
    player_ = OH_AVPlayer_Create();
    OH_AVPlayer_SetOnInfoCallback(player_, OnInfoCallback, this);

    int32_t fd = open(MD, O_RDONLY);
    OH_AVPlayer_SetFDSource(player_, fd, 0, -1);
    WaitForStateWithCV(AVPlayerState::AV_INITIALIZED, WAIT_TIMEOUT_SHORT);

    OH_AVPlayer_Prepare(player_);
    WaitForStateWithCV(AVPlayerState::AV_PREPARED, WAIT_TIMEOUT_LONG);
}

void AVPlayerMp4UnitTest::TearDown(void)
{
    if (player_ != nullptr) {
        OH_AVPlayer_ReleaseSync(player_);
        player_ = nullptr;
    }
}

void AVPlayerMp4UnitTest::WaitForStateWithCV(AVPlayerState targetState, int32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto timeout = std::chrono::milliseconds(timeoutMs);

    bool success = cv_.wait_for(lock, timeout, [this, targetState]() {
        return currentState_ == targetState;
    });

    ASSERT_TRUE(success) << "Timeout waiting for state " << targetState;
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest001
 * @tc.desc: Test set playback range
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SetPlaybackRangeTest001, Level1)
{
    ASSERT_NE(player_, nullptr);
    int64_t mSecondsStart = -1;
    int64_t mSecondsEnd = -1;
    bool closestRange = true;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player_, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest002
 * @tc.desc: Test set playback range with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetPlaybackRangeTest002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    int64_t mSecondsStart = -1;
    int64_t mSecondsEnd = -1;
    bool closestRange = true;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest003
 * @tc.desc: Test set playback range with invalid state
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetPlaybackRangeTest003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    int64_t mSecondsStart = -1;
    int64_t mSecondsEnd = -1;
    bool closestRange = true;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_OPERATE_NOT_PERMIT, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest004
 * @tc.desc: Test set playback range with invalid mSecondsStart
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SetPlaybackRangeTest004, Level1)
{
    ASSERT_NE(player_, nullptr);
    int64_t mSecondsStart = -2;
    int64_t mSecondsEnd = -1;
    bool closestRange = true;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player_, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest005
 * @tc.desc: Test set playback range with invalid mSecondsEnd
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SetPlaybackRangeTest005, Level1)
{
    ASSERT_NE(player_, nullptr);
    int64_t mSecondsStart = -1;
    int64_t mSecondsEnd = -2;
    bool closestRange = true;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player_, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetPlaybackRangeTest006
 * @tc.desc: Test set playback range
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SetPlaybackRangeTest006, Level1)
{
    ASSERT_NE(player_, nullptr);
    int64_t mSecondsStart = -1;
    int64_t mSecondsEnd = -1;
    bool closestRange = false;
    OH_AVErrCode ret = OH_AVPlayer_SetPlaybackRange(player_, mSecondsStart, mSecondsEnd, closestRange);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaMutedTest001
 * @tc.desc: Test set media muted
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SetMediaMutedTest001, Level1)
{
    ASSERT_NE(player_, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SetMediaMuted(player_, OH_MediaType::MEDIA_TYPE_AUD, true);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaMutedTest002
 * @tc.desc: Test set media muted with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaMutedTest002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SetMediaMuted(player, OH_MediaType::MEDIA_TYPE_AUD, true);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SetMediaMutedTest003
 * @tc.desc: Test set media muted with state is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SetMediaMutedTest003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SetMediaMuted(player, OH_MediaType::MEDIA_TYPE_AUD, true);
    ASSERT_EQ(AV_ERR_OPERATE_NOT_PERMIT, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSource001
 * @tc.desc: Test add subtitle source from network url with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_AddUrlSubtitleSource001, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    const char* url = "nullptr";
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player, url);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSource002
 * @tc.desc: Test add subtitle source from network url with url is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_AddUrlSubtitleSource002, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    const char* url = nullptr;
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player, url);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSource003
 * @tc.desc: Test add subtitle source from network url with url is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_AddUrlSubtitleSource003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    const char* url = "nullptr";
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player, url);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSourceWithNetWork001
 * @tc.desc: Test add subtitle source from network url
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_AddUrlSubtitleSourceWithNetWork001, Level1)
{
    ASSERT_NE(player_, nullptr);
    const char* url = ISNETWORK_SUBTITLE_URL;
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player_, url);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSourceWithFd001
 * @tc.desc: Test add subtitle source from fd url
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_AddUrlSubtitleSourceWithFd001, Level1)
{
    ASSERT_NE(player_, nullptr);
    int32_t fd = open(LOCAL_SUBTITLE_PATH, O_RDONLY);
    std::string fdUrl = "fd://" + std::to_string(fd);
    const char* url = fdUrl.c_str();
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player_, url);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddUrlSubtitleSourceWithFd002
 * @tc.desc: Test add subtitle source from fd url with invalid fd
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_AddUrlSubtitleSourceWithFd002, Level1)
{
    ASSERT_NE(player_, nullptr);
    std::string fdUrl = "fd://";
    const char* url = fdUrl.c_str();
    OH_AVErrCode ret = OH_AVPlayer_AddUrlSubtitleSource(player_, url);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddFdSubtitleSource001
 * @tc.desc: Test add subtitle source from fd
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_AddFdSubtitleSource001, Level1)
{
    ASSERT_NE(player_, nullptr);
    int32_t fd = open(LOCAL_SUBTITLE_PATH, O_RDONLY);
    int64_t offset = 0;
    int64_t size = -1;
    OH_AVErrCode ret = OH_AVPlayer_AddFdSubtitleSource(player_, fd, offset, size);
    close(fd);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddFdSubtitleSource002
 * @tc.desc: Test add subtitle source from fd with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_AddFdSubtitleSource002, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    int32_t fd = open(LOCAL_SUBTITLE_PATH, O_RDONLY);
    int64_t offset = 0;
    int64_t size = -1;
    OH_AVErrCode ret = OH_AVPlayer_AddFdSubtitleSource(player, fd, offset, size);
    close(fd);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_AddFdSubtitleSource003
 * @tc.desc: Test add subtitle source from fd
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_AddFdSubtitleSource003, Level1)
{
    ASSERT_NE(player_, nullptr);
    int32_t fd = open(LOCAL_SUBTITLE_PATH, O_RDONLY);
    int64_t offset = -1;
    int64_t size = -2;
    OH_AVErrCode ret = OH_AVPlayer_AddFdSubtitleSource(player_, fd, offset, size);
    close(fd);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_IsSeekContinuousSupported001
 * @tc.desc: Test is seek continuous supported with is false
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_IsSeekContinuousSupported001, Level1)
{
    ASSERT_NE(player_, nullptr);
    bool isSeek = OH_AVPlayer_IsSeekContinuousSupported(player_);
    ASSERT_EQ(false, isSeek);
}

/**
 * @tc.name: OH_AVPlayer_IsSeekContinuousSupported002
 * @tc.desc: Test is seek continuous supported with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_IsSeekContinuousSupported002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    bool isSeek = OH_AVPlayer_IsSeekContinuousSupported(player);
    ASSERT_EQ(false, isSeek);
}

/**
 * @tc.name: OH_AVPlayer_IsSeekContinuousSupported003
 * @tc.desc: Test is seek continuous supported with isReleased is ture
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_IsSeekContinuousSupported003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVPlayer_ReleaseSync(player);
    bool isSeek = OH_AVPlayer_IsSeekContinuousSupported(player);
    ASSERT_EQ(false, isSeek);
}

/**
 * @tc.name: OH_AVPlayer_SelectTrackWithMode001
 * @tc.desc: Test set Track with mode
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_SelectTrackWithMode001, Level1)
{
    ASSERT_NE(player_, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SelectTrackWithMode(player_, 0, AV_TRACK_SWITCH_MODE_SMOOTH);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVPlayer_SelectTrackWithMode002
 * @tc.desc: Test set Track with mode with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SelectTrackWithMode002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SelectTrackWithMode(player, 0, AV_TRACK_SWITCH_MODE_SMOOTH);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SelectTrackWithMode003
 * @tc.desc: Test set Track with mode with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SelectTrackWithMode003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SelectTrackWithMode(player, -1, AV_TRACK_SWITCH_MODE_SMOOTH);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SelectTrackWithMode004
 * @tc.desc: Test set Track with mode with mode is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SelectTrackWithMode004, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SelectTrackWithMode(player, 0, static_cast<AVPlayerTrackSwitchMode>(3));
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_SelectTrackWithMode005
 * @tc.desc: Test set Track with mode with mode is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_SelectTrackWithMode005, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_SelectTrackWithMode(player, 0, AV_TRACK_SWITCH_MODE_SMOOTH);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackInfo001
 * @tc.desc: Test get playback info
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackInfo001, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetPlaybackInfo(player);
    ASSERT_EQ(avformat, nullptr);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackInfo002
 * @tc.desc: Test get playback info with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackInfo002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetPlaybackInfo(player);
    ASSERT_EQ(avformat, nullptr);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackInfo003
 * @tc.desc: Test get playback info with player is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetPlaybackInfo003, Level1)
{
    ASSERT_NE(player_, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetPlaybackInfo(player_);
    ASSERT_NE(avformat, nullptr);
    OH_AVFormat_Destroy(avformat);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackCount001
 * @tc.desc: Test get track count
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetTrackCount001, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    uint32_t trackCount = OH_AVPlayer_GetTrackCount(player);
    ASSERT_EQ(trackCount, 0);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackCount002
 * @tc.desc: Test get track count with not 0
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetTrackCount002, Level1)
{
    ASSERT_NE(player_, nullptr);
    uint32_t trackCount = OH_AVPlayer_GetTrackCount(player_);
    ASSERT_NE(trackCount, 0);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackCount003
 * @tc.desc: Test get track count with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetTrackCount003, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    uint32_t trackCount = OH_AVPlayer_GetTrackCount(player);
    ASSERT_EQ(trackCount, 0);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackFormat001
 * @tc.desc: Test get track format
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetTrackFormat001, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetTrackFormat(player, 0);
    ASSERT_EQ(avformat, nullptr);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackFormat002
 * @tc.desc: Test get track format with not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetTrackFormat002, Level1)
{
    ASSERT_NE(player_, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetTrackFormat(player_, 0);
    ASSERT_NE(avformat, nullptr);
    OH_AVFormat_Destroy(avformat);
}

/**
 * @tc.name: OH_AVPlayer_GetTrackFormat003
 * @tc.desc: Test get track format with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetTrackFormat003, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    OH_AVFormat *avformat = OH_AVPlayer_GetTrackFormat(player, 0);
    ASSERT_EQ(avformat, nullptr);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackSpeed001
 * @tc.desc: Test get playback speed
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetPlaybackSpeed001, Level1)
{
    ASSERT_NE(player_, nullptr);
    AVPlaybackSpeed speedSet = AV_SPEED_FORWARD_1_00_X;
    OH_AVErrCode res = OH_AVPlayer_SetPlaybackSpeed(player_, speedSet);
    ASSERT_EQ(AV_ERR_OK, res);

    AVPlaybackSpeed speed = AV_SPEED_FORWARD_0_75_X;
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackSpeed(player_, &speed);
    ASSERT_EQ(AV_ERR_OK, ret);
    ASSERT_EQ(speed, AV_SPEED_FORWARD_1_00_X);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackSpeed002
 * @tc.desc: Test get playback speed with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackSpeed002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    AVPlaybackSpeed speed = AV_SPEED_FORWARD_0_75_X;
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackSpeed(player, &speed);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
    ASSERT_EQ(speed, AV_SPEED_FORWARD_0_75_X);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackSpeed003
 * @tc.desc: Test get playback speed with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackSpeed003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackSpeed(player, nullptr);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackRate001
 * @tc.desc: Test get playback rate
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetPlaybackRate001, Level1)
{
    ASSERT_NE(player_, nullptr);
    float speedSet = 1.0f;
    OH_AVErrCode res = OH_AVPlayer_SetPlaybackRate(player_, speedSet);
    ASSERT_EQ(AV_ERR_OK, res);

    float speed = 0.75f;
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackRate(player_, &speed);
    ASSERT_EQ(AV_ERR_OK, ret);
    ASSERT_EQ(speed, 1.0f);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackRate002
 * @tc.desc: Test get playback rate with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackRate002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    float speed = 0.75f;
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackRate(player, &speed);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
    ASSERT_EQ(speed, 0.75f);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackRate003
 * @tc.desc: Test get playback rate with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackRate003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    OH_AVErrCode ret = OH_AVPlayer_GetPlaybackRate(player, nullptr);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackPosition001
 * @tc.desc: Test get playback position
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerMp4UnitTest, OH_AVPlayer_GetPlaybackPosition001, Level1)
{
    ASSERT_NE(player_, nullptr);
    int32_t position = OH_AVPlayer_GetPlaybackPosition(player_);
    ASSERT_EQ(position, 0);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackPosition002
 * @tc.desc: Test get playback position with player is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackPosition002, Level1)
{
    OH_AVPlayer *player = nullptr;
    ASSERT_EQ(player, nullptr);
    int32_t position = OH_AVPlayer_GetPlaybackPosition(player);
    ASSERT_EQ(position, -1);
}

/**
 * @tc.name: OH_AVPlayer_GetPlaybackPosition003
 * @tc.desc: Test get playback position with state is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVPlayerUnitTest, OH_AVPlayer_GetPlaybackPosition003, Level1)
{
    OH_AVPlayer *player = OH_AVPlayer_Create();
    ASSERT_NE(player, nullptr);
    int32_t position = OH_AVPlayer_GetPlaybackPosition(player);
    ASSERT_EQ(position, -1);
}
