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

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
/**
* @tc.name: CheckCaptureMode_001
* @tc.desc: captureMode < CAPTURE_HOME_SCREEN
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_001, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->CheckCaptureMode(CaptureMode::CAPTURE_INVAILD);
    ASSERT_NE(ret, MSERR_OK);
}

/**
* @tc.name: CheckCaptureMode_002
* @tc.desc: captureMode > CAPTURE_SPECIFIED_WINDOW
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_002, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->CheckCaptureMode(static_cast<CaptureMode>
        (CaptureMode::CAPTURE_SPECIFIED_WINDOW + 1));
    ASSERT_NE(ret, MSERR_OK);
}

/**
* @tc.name: CheckAudioCapParam_002
* @tc.desc: audioSource > APP_PLAYBACK
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioCapParam_002, TestSize.Level2)
{
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = static_cast<AudioCaptureSourceType>(AudioCaptureSourceType::APP_PLAYBACK + 1)
    };
    ASSERT_NE(screenCaptureServer_->CheckAudioCapParam(micCapInfo), MSERR_OK);
}

/**
* @tc.name: CheckVideoEncParam_006
* @tc.desc: videoCodec < VIDEO_DEFAULT
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_006, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoEncInfo.videoCodec = static_cast<VideoCodecFormat>(VideoCodecFormat::VIDEO_DEFAULT - 1);
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioCapInfo_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.micCapInfo.audioChannels = 0;
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    ASSERT_NE(screenCaptureServer_->CheckAudioCapInfo(config_.audioInfo.micCapInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoCapInfo_001, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1080;
    ASSERT_NE(screenCaptureServer_->CheckVideoCapInfo(config_.videoInfo.videoCapInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_001, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0;
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_002, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_001, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5;
    area.h = 5;
    bool ret = screenCaptureServer_->CheckDisplayArea(0, area);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_002, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5;
    area.h = 5;
    bool ret = screenCaptureServer_->CheckDisplayArea(10, area);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_003, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5000;
    area.h = 5000;
    bool ret = screenCaptureServer_->CheckDisplayArea(0, area);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_001, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 20;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(801);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_002, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 18;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(801);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_003, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 20;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(202);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_004, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 18;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(202);
    EXPECT_EQ(ret, false);
}
} // Media
} // OHOS