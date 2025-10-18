/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "recordersetcaptureratefounction_fuzzer.h"
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "recorder.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;
using namespace PlayerTestParam;
using namespace RecorderTestParam;

namespace OHOS {
namespace Media {
RecorderSetCaptureRateFouncFuzzer::RecorderSetCaptureRateFouncFuzzer()
{
}

RecorderSetCaptureRateFouncFuzzer::~RecorderSetCaptureRateFouncFuzzer()
{
}

bool RecorderSetCaptureRateFouncFuzzer::FuzzRecorderSetCaptureRate(uint8_t *data, size_t size)
{
    constexpr int32_t audioMaxFileSize = 5000;
    RETURN_IF(TestRecorder::CreateRecorder(), false);

    static VideoRecorderConfig_ g_videoRecorderConfig;
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = MPEG4;

    TestRecorder::SetVideoSource(g_videoRecorderConfig);
    TestRecorder::CameraServicesForVideo(g_videoRecorderConfig);
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isHdr = GetData<bool>();
    bool temporalScale = GetData<bool>();
    bool qualityMode = GetData<bool>();
    bool enableBFrame = GetData<bool>();
    bool isWatermark = GetData<bool>();
    bool whenInterrupted = GetData<bool>();
    TestRecorder::SetVideoIsHdr(g_videoRecorderConfig.audioSourceId, isHdr);
    TestRecorder::SetVideoEnableTemporalScale(g_videoRecorderConfig.audioSourceId, temporalScale);
    TestRecorder::SetVideoEnableStableQualityMode(g_videoRecorderConfig.audioSourceId, qualityMode );
    TestRecorder::SetVideoEnableBFrame(g_videoRecorderConfig.audioSourceId, enableBFrame);

    TestRecorder::GetMetaSurface(g_videoRecorderConfig.audioSourceId);
    TestRecorder::SetMetaConfigs(g_videoRecorderConfig.audioSourceId);
    TestRecorder::GetMaxAmplitude();
    TestRecorder::IsWatermarkSupported(isWatermark);
    TestRecorder::SetWillMuteWhenInterrupted(whenInterrupted);
    return true;
}
}

bool FuzzTestRecorderSetCaptureRate(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(double)) {
        return true;
    }
    RecorderSetCaptureRateFouncFuzzer testRecorder;
    return testRecorder.FuzzRecorderSetCaptureRate(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestRecorderSetCaptureRate(data, size);
    return 0;
}

