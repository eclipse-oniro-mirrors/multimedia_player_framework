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
#ifndef SCREEN_CAPTURE_SERVER_FUNCTION_UNITTEST_H
#define SCREEN_CAPTURE_SERVER_FUNCTION_UNITTEST_H

#include <fcntl.h>
#include <iostream>
#include <string>
#include <nativetoken_kit.h>
#include "media_errors.h"
#include "media_utils.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "screen_capture_listener_proxy.h"
#include "screen_capture_server.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Media {
namespace ScreenCaptureTestParam {
constexpr uint32_t RECORDER_TIME = 2;
}
class ScreenCaptureServerFunctionTest : public testing::Test {
public:
    virtual void SetUp();
    virtual void TearDown();
    int32_t SetInvalidConfig();
    int32_t SetValidConfig();
    int32_t SetInvalidConfigFile(RecorderInfo &recorderInfo);
    int32_t SetValidConfigFile(RecorderInfo &recorderInfo);
    int32_t SetRecorderInfo(std::string name, RecorderInfo &recorderInfo);
    void OpenFileFd(std::string name);
    int32_t InitFileScreenCaptureServer();
    int32_t InitStreamScreenCaptureServer();
    void SetHapPermission();
    int32_t SetScreenCaptureObserver();
    int32_t StartFileAudioCapture();
    int32_t StartStreamAudioCapture();

protected:
    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_;
    AVScreenCaptureConfig config_;
    int32_t outputFd_ = -1;
private:
    const std::string ScreenRecorderBundleName =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
};

class StandardScreenCaptureServerUnittestCallback : public IStandardScreenCaptureListener {
public:
    virtual ~StandardScreenCaptureServerUnittestCallback() = default;
    sptr<IRemoteObject> AsObject() { return nullptr; };
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) {};
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) {};
    void OnVideoBufferAvailable(bool isReady) {};
    void OnStateChange(AVScreenCaptureStateCode stateCode) {};
};

class ScreenCaptureServerUnittestCallback : public ScreenCaptureListenerCallback {
public:
    virtual ~ScreenCaptureServerUnittestCallback() = default;
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) {};
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) {};
    void OnVideoBufferAvailable(bool isReady) {};
    void OnStateChange(AVScreenCaptureStateCode stateCode) {};
    void Stop() {};
};
} // Media
} // OHOS
#endif