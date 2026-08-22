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

#include "screen_capture_service_providers_unittest.h"
#include "account_observer.h"
#include "i_recorder_service.h"
#include "i_screen_capture_monitor_service.h"
#include "media_errors.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {

void ScreenCaptureServiceProvidersTest::SetUpTestCase(void) {}

void ScreenCaptureServiceProvidersTest::TearDownTestCase(void) {}

void ScreenCaptureServiceProvidersTest::SetUp(void)
{
    providers_ = CreateDefaultProviders();
    ASSERT_NE(providers_, nullptr);
}

void ScreenCaptureServiceProvidersTest::TearDown(void)
{
    providers_ = nullptr;
}

/**
 * @tc.name    : CreateDefaultProviders_001
 * @tc.number  : CreateDefaultProviders_001
 * @tc.desc    : Test CreateDefaultProviders returns a valid provider instance
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, CreateDefaultProviders_001, TestSize.Level1)
{
    auto providers = CreateDefaultProviders();
    ASSERT_NE(providers, nullptr);
    AccountObserver &observer1 = providers->GetAccountObserver();
    AccountObserver &observer2 = providers_->GetAccountObserver();
    EXPECT_EQ(&observer1, &observer2);
}

/**
 * @tc.name    : GetScreenCaptureMonitor_001
 * @tc.number  : GetScreenCaptureMonitor_001
 * @tc.desc    : Test GetScreenCaptureMonitor returns a valid service reference
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, GetScreenCaptureMonitor_001, TestSize.Level1)
{
    IInnerScreenCaptureMonitorService &monitor = providers_->GetScreenCaptureMonitor();
    EXPECT_NE(&monitor, nullptr);
}

/**
 * @tc.name    : GetScreenCaptureMonitor_002
 * @tc.number  : GetScreenCaptureMonitor_002
 * @tc.desc    : Test GetScreenCaptureMonitor returns the same singleton on each call
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, GetScreenCaptureMonitor_002, TestSize.Level1)
{
    IInnerScreenCaptureMonitorService &monitor1 = providers_->GetScreenCaptureMonitor();
    IInnerScreenCaptureMonitorService &monitor2 = providers_->GetScreenCaptureMonitor();
    EXPECT_EQ(&monitor1, &monitor2);
}

/**
 * @tc.name    : CreateRecorder_001
 * @tc.number  : CreateRecorder_001
 * @tc.desc    : Test CreateRecorder returns a valid recorder instance
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, CreateRecorder_001, TestSize.Level1)
{
    std::shared_ptr<IRecorderService> recorder = providers_->CreateRecorder();
    EXPECT_NE(recorder, nullptr);
}

/**
 * @tc.name    : CreateRecorder_002
 * @tc.number  : CreateRecorder_002
 * @tc.desc    : Test CreateRecorder returns distinct instances on each call
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, CreateRecorder_002, TestSize.Level1)
{
    auto recorder1 = providers_->CreateRecorder();
    auto recorder2 = providers_->CreateRecorder();
    EXPECT_NE(recorder1, nullptr);
    EXPECT_NE(recorder2, nullptr);
    EXPECT_NE(recorder1, recorder2);
}

/**
 * @tc.name    : GetAccountObserver_001
 * @tc.number  : GetAccountObserver_001
 * @tc.desc    : Test GetAccountObserver returns a valid observer reference
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, GetAccountObserver_001, TestSize.Level1)
{
    AccountObserver &observer = providers_->GetAccountObserver();
    EXPECT_NE(&observer, nullptr);
}

/**
 * @tc.name    : GetAccountObserver_002
 * @tc.number  : GetAccountObserver_002
 * @tc.desc    : Test GetAccountObserver returns the same singleton on each call
 */
HWTEST_F(ScreenCaptureServiceProvidersTest, GetAccountObserver_002, TestSize.Level1)
{
    AccountObserver &observer1 = providers_->GetAccountObserver();
    AccountObserver &observer2 = providers_->GetAccountObserver();
    EXPECT_EQ(&observer1, &observer2);
}

} // namespace Media
} // namespace OHOS
