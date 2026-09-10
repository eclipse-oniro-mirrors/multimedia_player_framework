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

#include "screen_capture_server_function_unittest.h"
#include "screen_capture_controller_server.h"
#include "screen_capture_server_manager.h"
#include "media_errors.h"
#include <gtest/gtest.h>

using namespace testing::ext;

extern "C" {
__attribute__((visibility("default"))) OHOS::Media::IScreenCaptureController *CreateScreenCaptureControllerServer();
__attribute__((visibility("default"))) void DestroyScreenCaptureControllerServer(
    OHOS::Media::IScreenCaptureController *controller);
}

namespace {
constexpr int32_t TEST_INVALID_SESSION = -1;
}

namespace OHOS {
namespace Media {

class ScreenCaptureControllerServerFunctionTest : public testing::Test {
public:
    void SetUp() override
    {
        server_ = MakeScreenCaptureServerShared();
        ASSERT_NE(server_, nullptr);
        sessionId_ = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
        server_->sessionId_ = sessionId_;
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId_, server_, server_->appInfo_.appUid);
    }
    void TearDown() override
    {
        ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId_);
        if (server_) {
            server_->Release();
            server_ = nullptr;
        }
    }

protected:
    std::shared_ptr<ScreenCaptureServer> server_;
    int32_t sessionId_ = -1;
};

HWTEST_F(ScreenCaptureControllerServerFunctionTest, ReportAVScreenCaptureUserChoice_InvalidSession_001, TestSize.Level2)
{
    auto controller = ScreenCaptureControllerServer::Create();
    ASSERT_NE(controller, nullptr);
    EXPECT_EQ(controller->ReportAVScreenCaptureUserChoice(TEST_INVALID_SESSION, "{}"), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureControllerServerFunctionTest, ReportAVScreenCaptureUserChoice_ValidSession_001, TestSize.Level2)
{
    auto controller = ScreenCaptureControllerServer::Create();
    ASSERT_NE(controller, nullptr);
    server_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    EXPECT_EQ(controller->ReportAVScreenCaptureUserChoice(sessionId_, "{\"choice\":\"true\"}"), MSERR_OK);
}

HWTEST_F(ScreenCaptureControllerServerFunctionTest, GetAVScreenCaptureConfigurableParameters_InvalidSession_001,
    TestSize.Level2)
{
    auto controller = ScreenCaptureControllerServer::Create();
    ASSERT_NE(controller, nullptr);
    std::string result = "untouched";
    EXPECT_EQ(controller->GetAVScreenCaptureConfigurableParameters(TEST_INVALID_SESSION, result), MSERR_UNKNOWN);
    EXPECT_EQ(result, "untouched");
}

HWTEST_F(ScreenCaptureControllerServerFunctionTest, GetAVScreenCaptureConfigurableParameters_ValidSession_001,
    TestSize.Level2)
{
    auto controller = ScreenCaptureControllerServer::Create();
    ASSERT_NE(controller, nullptr);
    std::string result;
    EXPECT_EQ(controller->GetAVScreenCaptureConfigurableParameters(sessionId_, result), MSERR_OK);
    EXPECT_FALSE(result.empty());
}
} // namespace Media
} // namespace OHOS
