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

#ifndef SCREENCAPTURESERVERSTARTCASE_FUZZER
#define SCREENCAPTURESERVERSTARTCASE_FUZZER

#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include "test_screen_capture.h"

#define FUZZ_PROJECT_NAME "screencaptureserverstartcase_fuzzer"

namespace OHOS {
namespace Media {
class ScreenCaptureServerStartCaseFuzzer : public TestScreenCapture {
public:
    ScreenCaptureServerStartCaseFuzzer();
    ~ScreenCaptureServerStartCaseFuzzer();
    void SetConfig(RecorderInfo &recorderInfo);
    bool FuzzScreenCaptureServerStartCase(uint8_t *data, size_t size);
    std::shared_ptr<TestScreenCapture> screenCapture = nullptr;
    AVScreenCaptureConfig config_;
};
} // namespace Media
bool FuzzTestScreenCaptureServerStartCase(uint8_t *data, size_t size);
} // namespace OHOS
#endif