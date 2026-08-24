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

#include "accesstoken_kit.h"
#include "media_errors.h"
#include "media_utils.h"
#include "mock/mock_audio_capturer.h"
#include "mock/mock_media_utils.h"
#include "mock/mock_screen_capture_service_providers.h"
#include "screen_capture_listener_callback.h"
#include "screen_capture_listener_proxy.h"
#include "screen_capture_server.h"
#include "token_setproc.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <fcntl.h>
#include <iostream>
#include <nativetoken_kit.h>
#include <string>
#include <vector>

extern "C" {
OHOS::Media::IScreenCaptureService *CreateScreenCaptureServer(OHOS::Media::IScreenCaptureServiceProviders *providers);
void DestroyScreenCaptureServer(OHOS::Media::IScreenCaptureService *server);
}

struct ScreenCaptureServerDeleter {
    void operator()(OHOS::Media::ScreenCaptureServer *p) const
    {
        DestroyScreenCaptureServer(static_cast<OHOS::Media::IScreenCaptureService *>(p));
    }
};

using ScreenCaptureServerPtr = std::unique_ptr<OHOS::Media::ScreenCaptureServer, ScreenCaptureServerDeleter>;

inline ScreenCaptureServerPtr MakeScreenCaptureServer()
{
    auto providers = OHOS::Media::CreateMockProviders();
    auto *raw = static_cast<OHOS::Media::ScreenCaptureServer *>(CreateScreenCaptureServer(providers.release()));
    return ScreenCaptureServerPtr(raw, ScreenCaptureServerDeleter());
}

inline std::shared_ptr<OHOS::Media::ScreenCaptureServer> MakeScreenCaptureServerShared()
{
    return std::make_shared<OHOS::Media::ScreenCaptureServer>(OHOS::Media::CreateMockProviders());
}

inline std::shared_ptr<OHOS::Media::ScreenCaptureServer> MakeScreenCaptureServerViaCreate()
{
    auto service = OHOS::Media::ScreenCaptureServer::Create(OHOS::Media::CreateMockProviders());
    if (service) {
        return std::static_pointer_cast<OHOS::Media::ScreenCaptureServer>(service);
    }
    return nullptr;
}

namespace OHOS {
namespace Media {
namespace ScreenCaptureTestParam {
constexpr uint32_t RECORDER_TIME = 2;
}

class ScreenCaptureServerFunctionTest : public testing::Test {
public:
    virtual void SetUp();
    virtual void TearDown();
    void WaitForTaskComplete();
    void SetMockBuilder(ScreenCaptureServer *server);
    int32_t SetInvalidConfig();
    std::shared_ptr<AVBuffer> CreateWatermarkBuffer();
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
    void SetSCInnerAudioCaptureAndPushData(std::shared_ptr<AudioBuffer> innerAudioBuffer);
    void SetSCMicAudioCaptureAndPushData(std::shared_ptr<AudioBuffer> micAudioBuffer);
    std::shared_ptr<AudioCapturerWrapper> CreateTestWrapper(AudioCaptureInfo &audioInfo, const std::string &name,
        bool isInner = true);
    void SetupAudioDataSource(AVScreenCaptureMixMode mode);
    size_t CountForegroundMissions(const std::vector<MissionInfo> &missions);

protected:
    ScreenCaptureServerPtr screenCaptureServer_;
    AVScreenCaptureConfig config_;
    int32_t outputFd_ = -1;

private:
    const std::string ScreenRecorderBundleName = GetScreenCaptureSystemParam()
        ["const.multimedia.screencapture.screenrecorderbundlename"];
    Security::AccessToken::HapInfoParams info_ = {.userID = 100, // 100 UserID
        .bundleName = "com.ohos.test.screencapturetdd",
        .instIndex = 0, // 0 index
        .appIDDesc = "com.ohos.test.screencapturetdd",
        .isSystemApp = true};
    // clang-format off
    Security::AccessToken::HapPolicyParams policy_ = {
        .apl = Security::AccessToken::APL_SYSTEM_BASIC,
        .domain = "test.domain.screencapturetdd",
        .permList = {},
        .permStateList = {
            {
                .permissionName = "ohos.permission.MICROPHONE",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.READ_MEDIA",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.WRITE_MEDIA",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.KEEP_BACKGROUND_RUNNING",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.CAPTURE_SCREEN",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.TIMEOUT_SCREENOFF_DISABLE_LOCK",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            }
        }
    };
    // clang-format on
};

class StandardScreenCaptureServerUnittestCallback : public IStandardScreenCaptureListener {
public:
    virtual ~StandardScreenCaptureServerUnittestCallback() = default;
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) {};
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) {};
    void OnVideoBufferAvailable(bool isReady) {};
    void OnStateChange(AVScreenCaptureStateCode stateCode) {};
    void OnDisplaySelected(uint64_t displayId) {};
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area) {};
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) {};
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) {};
};

class ScreenCaptureServerUnittestCallbackMock : public ScreenCaptureListenerCallback {
public:
    explicit ScreenCaptureServerUnittestCallbackMock(const sptr<IStandardScreenCaptureListener> &listener)
        : ScreenCaptureListenerCallback(listener)
    {
    }
    virtual ~ScreenCaptureServerUnittestCallbackMock() = default;
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode);
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type);
    void OnVideoBufferAvailable(bool isReady);
    void OnStateChange(AVScreenCaptureStateCode stateCode);
    void OnDisplaySelected(uint64_t displayId);
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area);
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo);
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect);
    void Stop();
};
} // namespace Media
} // namespace OHOS
#endif
