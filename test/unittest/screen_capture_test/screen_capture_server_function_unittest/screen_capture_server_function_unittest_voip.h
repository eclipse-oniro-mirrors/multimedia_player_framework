/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_SERVER_FUNCTION_UNITTEST_VOIP_H
#define SCREEN_CAPTURE_SERVER_FUNCTION_UNITTEST_VOIP_H

#include <fcntl.h>
#include <iostream>
#include <string>
#include <nativetoken_kit.h>
#include "media_errors.h"
#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "screen_capture_server.h"

namespace OHOS {
namespace Media {
class ScreenCaptureServerFunctionTest : public testing::Test {
public:
    virtual void SetUp(void);
    virtual void TearDown(void);
    int32_t SetConfig();
    int32_t SetConfigFile(RecorderInfo &recorderInfo);
    int32_t SetRecorderInfo(std::string name, RecorderInfo &recorderInfo);
    void OpenFileFd(std::string name);
    int32_t InitScreenCaptureServer();
    static void SetHapPermission();
    int32_t SetScreenCaptureObserver();
    int32_t StartAudioCapture();

protected:
    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_ = nullptr;
    AVScreenCaptureConfig config_;
    int32_t outputFd_ = -1;
};
} // namespace Media
} // namespace OHOS
#endif