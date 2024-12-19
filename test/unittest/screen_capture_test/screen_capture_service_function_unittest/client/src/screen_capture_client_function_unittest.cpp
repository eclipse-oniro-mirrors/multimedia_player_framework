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

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_client_function_unittest.h"
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
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureClientFunctionTest"};
}

namespace OHOS {
namespace Media {

void ScreenCaptureClientFunctionTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info_, policy_);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

void ScreenCaptureClientFunctionTest::SetUp()
{
    SetHapPermission();
    // create client
    screenCaptureClient_ = ScreenCaptureClient::Create(nullptr);

    // create controller client
    screenCaptureClientController_ = ScreenCaptureControllerClient::Create(nullptr);
}

void ScreenCaptureClientFunctionTest::TearDown()
{
    if (screenCaptureClient_) {
        screenCaptureClient_->Release();
        screenCaptureClient_ = nullptr;
    }
    if (screenCaptureClient_) {
        screenCaptureClientController_ = nullptr;
    }
}

HWTEST_F(ScreenCaptureClientFunctionTest, MediaServiceDied_001, TestSize.Level2)
{
    screenCaptureClient_->MediaServerDied();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    ASSERT_EQ(screenCaptureClient_->SetScreenCaptureCallback(screenCaptureCb), MSERR_OK);
    screenCaptureClient_->MediaServerDied();
    screenCaptureClientController_->MediaServerDied();
}

HWTEST_F(ScreenCaptureClientFunctionTest, MediaServiceDied_002, TestSize.Level2)
{
    screenCaptureClient_->MediaServerDied();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    ASSERT_EQ(screenCaptureClient_->SetScreenCaptureCallback(screenCaptureCb), MSERR_OK);
    screenCaptureClient_->MediaServerDied();
    screenCaptureClientController_->MediaServerDied();

    (void)screenCaptureClient_->screenCaptureProxy_->DestroyStub();
    (void)screenCaptureClient_->screenCaptureProxy_ = nullptr;

    (void)screenCaptureClientController_->screenCaptureControllerProxy_->DestroyStub();
    (void)screenCaptureClientController_->screenCaptureControllerProxy_ = nullptr;
}
} // Media
} // OHOS