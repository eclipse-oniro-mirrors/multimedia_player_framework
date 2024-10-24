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

#ifndef SCREENCAPTURESETMAXFRAMERATENDK_FUZZER
#define SCREENCAPTURESETMAXFRAMERATENDK_FUZZER

#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include "test_ndk_screen_capture.h" // NDK screen capture test header included for testing purposes.

#define FUZZ_PROJECT_NAME "ScreenCaptureMaxFramerateNdkFuzzer"

namespace OHOS {
namespace Media {
class ScreenCaptureSetMaxFrameRateNdkFuzzer : public TestNdkScreenCapture {
public:
    ScreenCaptureSetMaxFrameRateNdkFuzzer();
    ~ScreenCaptureSetMaxFrameRateNdkFuzzer();
    bool FuzzScreenCaptureSetMaxFrameRateNdk(uint8_t *data, size_t size);
    OH_AVScreenCapture* screenCapture = nullptr;
    std::shared_ptr<TestScreenCaptureNdkCallback> screenCaptureCb = nullptr;
};
} // namespace Media
bool FuzzTestScreenCaptureSetMaxFrameRateNdk(uint8_t *data, size_t size);
} // namespace OHOS
#endif