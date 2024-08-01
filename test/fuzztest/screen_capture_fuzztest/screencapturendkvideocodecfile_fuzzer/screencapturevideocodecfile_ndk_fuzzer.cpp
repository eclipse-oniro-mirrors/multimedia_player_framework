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

#include <cmath>
#include <cstdlib>
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_log.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "screencapturevideocodecfile_ndk_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE,
                                               "ScreenCaptureVideoCodecFileNdkFuzzer"};
}

namespace OHOS {
namespace Media {
ScreenCaptureVideoCodecFileNdkFuzzer::ScreenCaptureVideoCodecFileNdkFuzzer()
{
}

ScreenCaptureVideoCodecFileNdkFuzzer::~ScreenCaptureVideoCodecFileNdkFuzzer()
{
}

void SetConfig(OH_AVScreenCaptureConfig &config)
{
    OH_AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = OH_ALL_PLAYBACK
    };

    OH_AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
        .audioCodecformat = OH_AudioCodecFormat::OH_AAC_LC
    };

    OH_VideoCaptureInfo videoCapInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1080,
        .videoSource = OH_VIDEO_SOURCE_SURFACE_RGBA
    };

    OH_VideoEncInfo videoEncInfo = {
        .videoCodec = OH_VideoCodecFormat::OH_MPEG4,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };

    OH_AudioInfo audioInfo = {
        .innerCapInfo = innerCapInfo,
        .audioEncInfo = audioEncInfo
    };

    OH_VideoInfo videoInfo = {
        .videoCapInfo = videoCapInfo,
        .videoEncInfo = videoEncInfo
    };

    config = {
        .captureMode = OH_CAPTURE_HOME_SCREEN,
        .dataType = OH_CAPTURE_FILE,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo,
    };
}

bool ScreenCaptureVideoCodecFileNdkFuzzer::FuzzScreenCaptureVideoCodecFileNdk(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    screenCapture = OH_AVScreenCapture_Create();

    OH_AVScreenCaptureConfig config;
    SetConfig(config);
    constexpr int32_t videoCodecList = 7;
    constexpr uint32_t recorderTime = 3;
    const OH_VideoCodecFormat videoCodec[videoCodecList] {
        OH_VIDEO_DEFAULT,
        OH_H264,
        OH_H265,
        OH_MPEG4,
        OH_VP8,
        OH_VP9,
        OH_VIDEO_CODEC_FORMAT_BUTT
    };
    int32_t randomNum = abs((*reinterpret_cast<int32_t *>(data)) % (videoCodecList));
    MEDIA_LOGI("FuzzTest ScreenCaptureVideoCodecFileNdkFuzzer randomNum: %{public}d ", randomNum);

    config.videoInfo.videoEncInfo.videoCodec = videoCodec[randomNum];
    
    OH_RecorderInfo recorderInfo;
    const std::string screenCaptureRoot = "/data/test/media/";
    int32_t outputFd = open((screenCaptureRoot + "screen_capture_fuzz_ndk_videocodec_file_01.mp4").c_str(),
        O_RDWR | O_CREAT, 0777);
    std::string fileUrl = "fd://" + to_string(outputFd);
    recorderInfo.url = const_cast<char *>(fileUrl.c_str());
    recorderInfo.fileFormat = OH_ContainerFormatType::CFT_MPEG_4;
    config.recorderInfo = recorderInfo;

    OH_AVScreenCapture_Init(screenCapture, config);
    OH_AVScreenCapture_StartScreenCapture(screenCapture);
    sleep(recorderTime);
    OH_AVScreenCapture_StopScreenCapture(screenCapture);
    OH_AVScreenCapture_Release(screenCapture);
    return true;
}
} // namespace Media

bool FuzzTestScreenCaptureVideoCodecFileNdk(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureVideoCodecFileNdkFuzzer testScreenCapture;
    return testScreenCapture.FuzzScreenCaptureVideoCodecFileNdk(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    MEDIA_LOGI("FuzzTest ScreenCaptureVideoCodecFileNdkFuzzer start");
    MEDIA_LOGI("FuzzTest ScreenCaptureVideoCodecFileNdkFuzzer data: %{public}d ", *data);
    /* Run your code on data */
    OHOS::FuzzTestScreenCaptureVideoCodecFileNdk(data, size);
    MEDIA_LOGI("FuzzTest ScreenCaptureVideoCodecFileNdkFuzzer end");
    return 0;
}