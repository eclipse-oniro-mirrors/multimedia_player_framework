/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "lpp_engine_manager_unit_test.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Media {
void LppEngineManagerUnitTest::SetUpTestCase(void)
{
}

void LppEngineManagerUnitTest::TearDownTestCase(void)
{
}

void LppEngineManagerUnitTest::SetUp(void)
{
    lppEngineManager_ = std::make_shared<ILppEngineManager>();
}

void LppEngineManagerUnitTest::TearDown(void)
{
    lppEngineManager_ = nullptr;
}

/**
* @tc.name    : Test GetLppVideoInstance API
* @tc.number  : GetLppVideoInstance_001
* @tc.desc    : Test GetLppVideoInstance interface
*/
HWTEST_F(LppEngineManagerUnitTest, GetLppVideoInstance_001, TestSize.Level0)
{
    string videoStreamName = "video1";
    auto instance = std::make_shared<ILppVideoStreamerEngine>();
    lppEngineManager_->lppVideoStreamerMap_[videoStreamName] = instance;
    std::shared_ptr<ILppVideoStreamerEngine> ret = lppEngineManager_->GetLppVideoInstance(videoStreamName);
    EXPECT_NE(ret, nullptr);
    lppEngineManager_->lppVideoStreamerMap_.clear();
    ret = lppEngineManager_->GetLppVideoInstance(videoStreamName);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name    : Test GetLppAudioInstance API
* @tc.number  : GetLppAudioInstance_001
* @tc.desc    : Test GetLppAudioInstance interface
*/
HWTEST_F(LppEngineManagerUnitTest, GetLppAudioInstance_001, TestSize.Level0)
{
    string audioStreamName = "audio1";
    auto instance = std::make_shared<ILppAudioStreamerEngine>();
    lppEngineManager_->lppAudioStreamerMap_[audioStreamName] = instance;
    std::shared_ptr<ILppAudioStreamerEngine> ret = lppEngineManager_->GetLppAudioInstance(audioStreamName);
    EXPECT_NE(ret, nullptr);
    lppEngineManager_->lppAudioStreamerMap_.clear();
    ret = lppEngineManager_->GetLppAudioInstance(audioStreamName);
    EXPECT_EQ(ret, nullptr);
}

}  // namespace Media
}  // namespace OHOS