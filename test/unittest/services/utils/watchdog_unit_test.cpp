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

#include "watchdog_unit_test.h"

#include <thread>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace {
constexpr uint32_t TIMEOUT_MS = 1000;
}

namespace OHOS {
namespace Media {
namespace Test {
void WatchdogUnitTest::SetUpTestCase(void) {}

void WatchdogUnitTest::TearDownTestCase(void) {}

void WatchdogUnitTest::SetUp(void)
{
    watchDog_ = std::make_shared<WatchDog>(TIMEOUT_MS);
}

void WatchdogUnitTest::TearDown(void)
{
    watchDog_ = nullptr;
}

/**
 * @tc.name: PauseWatchDog
 * @tc.desc: PauseWatchDog
 * @tc.type: FUNC
 */
HWTEST_F(WatchdogUnitTest, PauseWatchDog, TestSize.Level1)
{
    watchDog_->enable_ = false;
    watchDog_->PauseWatchDog();

    watchDog_->enable_ = true;
    watchDog_->pause_ = false;
    watchDog_->paused_ = false;
    watchDog_->PauseWatchDog();
    ASSERT_EQ(watchDog_->pause_, true);
}

/**
 * @tc.name: ResumeWatchDog
 * @tc.desc: ResumeWatchDog
 * @tc.type: FUNC
 */
HWTEST_F(WatchdogUnitTest, ResumeWatchDog, TestSize.Level1)
{
    watchDog_->pause_ = true;
    watchDog_->enable_ = false;
    watchDog_->ResumeWatchDog();
    ASSERT_EQ(watchDog_->pause_, true);

    watchDog_->pause_ = true;
    watchDog_->enable_ = true;
    watchDog_->ResumeWatchDog();
    ASSERT_EQ(watchDog_->pause_, false);
}

/**
 * @tc.name: Notify
 * @tc.desc: Notify
 * @tc.type: FUNC
 */
HWTEST_F(WatchdogUnitTest, Notify, TestSize.Level1)
{
    watchDog_->pause_ = true;
    watchDog_->enable_ = false;
    watchDog_->alarmed_ = false;
    watchDog_->count_ = 0;
    watchDog_->Notify();
    ASSERT_EQ(watchDog_->pause_, true);
    ASSERT_EQ(watchDog_->alarmed_, false);
    ASSERT_EQ(watchDog_->count_, 0);

    watchDog_->pause_ = true;
    watchDog_->enable_ = true;
    watchDog_->alarmed_ = false;
    watchDog_->count_ = 0;
    watchDog_->Notify();
    ASSERT_EQ(watchDog_->pause_, true);
    ASSERT_EQ(watchDog_->alarmed_, false);
    ASSERT_EQ(watchDog_->count_, 1);

    watchDog_->pause_ = true;
    watchDog_->enable_ = true;
    watchDog_->alarmed_ = true;
    watchDog_->count_ = 0;
    watchDog_->Notify();
    ASSERT_EQ(watchDog_->pause_, false);
    ASSERT_EQ(watchDog_->alarmed_, false);
    ASSERT_EQ(watchDog_->count_, 1);
}

/**
 * @tc.name: ResumeWatchDog
 * @tc.desc: ResumeWatchDog
 * @tc.type: FUNC
 */
HWTEST_F(WatchdogUnitTest, WatchDogThread, TestSize.Level1)
{
    watchDog_->enable_ = false;
    watchDog_->pause_ = true;
    watchDog_->WatchDogThread();
    ASSERT_EQ(watchDog_->pause_, true);

    watchDog_->enable_ = false;
    watchDog_->pause_ = false;
    watchDog_->WatchDogThread();
    ASSERT_EQ(watchDog_->pause_, false);

    std::thread t([&watchDog = watchDog_] {
        usleep(500 * 1000);
        watchDog->enable_ = false;
        std::unique_lock<std::mutex> lock(watchDog->mutex_);
        watchDog->cond_.notify_all();
    });

    watchDog_->enable_ = true;
    watchDog_->pause_ = false;
    watchDog_->count_ = 1;
    watchDog_->paused_ = true;
    watchDog_->alarmed_ = true;
    watchDog_->WatchDogThread();
    ASSERT_EQ(watchDog_->pause_, false);

    if (t.joinable()) {
        t.join();
    }

    std::thread t1([&watchDog = watchDog_] {
        usleep(500 * 1000);
        watchDog->enable_ = false;
        std::unique_lock<std::mutex> lock(watchDog->mutex_);
        watchDog->cond_.notify_all();
    });

    watchDog_->enable_ = true;
    watchDog_->pause_ = false;
    watchDog_->count_ = 1;
    watchDog_->paused_ = true;
    watchDog_->alarmed_ = false;
    watchDog_->WatchDogThread();
    ASSERT_EQ(watchDog_->pause_, false);

    if (t1.joinable()) {
        t1.join();
    }
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS
