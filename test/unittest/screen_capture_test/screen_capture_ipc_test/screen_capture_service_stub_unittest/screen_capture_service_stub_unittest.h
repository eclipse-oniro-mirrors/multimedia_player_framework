/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_SERVICE_STUB_UNITTEST_H
#define SCREEN_CAPTURE_SERVICE_STUB_UNITTEST_H

#include "gtest/gtest.h"
#include "media_utils.h"
#include "screen_capture_service_stub.h"
namespace OHOS {
namespace Media {
class ScreenCaptureServiceStubTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    void SetHapPermission();
private:
    const std::string ScreenRecorderBundleName =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
    const std::string HiviewCareBundleName =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.hiviewcarebundlename"];
    Security::AccessToken::HapInfoParams info_ = {
        .userID = 100, // 100 UserID
        .bundleName = "com.ohos.test.screencapturetdd",
        .instIndex = 0, // 0 index
        .appIDDesc = "com.ohos.test.screencapturetdd",
        .isSystemApp = true
    };
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
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_STUB_UNITTEST_H