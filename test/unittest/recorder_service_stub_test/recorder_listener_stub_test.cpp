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

#include "recorder_listener_stub.h"
#include <memory>
#include <string>
#include "recorder.h"
#include "media_errors.h"
#include "media_log.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;

namespace {
class TestRecorderCallback : public RecorderCallback {
public:
    void OnError(RecorderErrorType errorType, int32_t errorCode) override
    {
        errorCount_++;
        lastErrorType_ = errorType;
        lastErrorCode_ = errorCode;
    }

    void OnInfo(int32_t type, int32_t extra) override
    {
        (void)type;
        infoCount_++;
        lastInfoExtra_ = extra;
    }

    void OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo) override
    {
        (void)audioRecorderChangeInfo;
        audioChangeCount_++;
    }

    void OnPhotoAssetAvailable(const std::string &uri) override
    {
        (void)uri;
        photoCount_++;
    }

    int32_t errorCount_ = 0;
    int32_t infoCount_ = 0;
    int32_t audioChangeCount_ = 0;
    int32_t photoCount_ = 0;
    RecorderErrorType lastErrorType_ = RECORDER_ERROR_INTERNAL;
    int32_t lastErrorCode_ = 0;
    int32_t lastInfoExtra_ = 0;
};
} // namespace

class RecorderListenerStubTest : public testing::Test {
public:
    void SetUp() override
    {
        stub_ = new RecorderListenerStub();
        ASSERT_NE(stub_, nullptr);
    }
    void TearDown() override
    {
        stub_ = nullptr;
    }

protected:
    sptr<RecorderListenerStub> stub_ = nullptr;
};

/**
 * @tc.name: Listener_OnError_WithCallback_001
 * @tc.desc: OnError forwards the error code to the registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnError_WithCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);

    stub_->OnError(static_cast<int32_t>(RECORDER_ERROR_INTERNAL), 1001);

    EXPECT_EQ(1, cb->errorCount_);
    EXPECT_EQ(RECORDER_ERROR_INTERNAL, cb->lastErrorType_);
    EXPECT_EQ(1001, cb->lastErrorCode_);
}

/**
 * @tc.name: Listener_OnError_NoCallback_001
 * @tc.desc: OnError is not delivered to a callback that has been unregistered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnError_NoCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->SetRecorderCallback(nullptr);

    stub_->OnError(static_cast<int32_t>(RECORDER_ERROR_INTERNAL), 1002);

    EXPECT_EQ(0, cb->errorCount_);
}

/**
 * @tc.name: Listener_OnInfo_WithCallback_001
 * @tc.desc: OnInfo forwards the extra info to the registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnInfo_WithCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->OnInfo(0, 42);
    EXPECT_EQ(1, cb->infoCount_);
    EXPECT_EQ(42, cb->lastInfoExtra_);
}

/**
 * @tc.name: Listener_OnInfo_NoCallback_001
 * @tc.desc: OnInfo is not delivered to a callback that has been unregistered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnInfo_NoCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->SetRecorderCallback(nullptr);

    stub_->OnInfo(0, 1);

    EXPECT_EQ(0, cb->infoCount_);
}

/**
 * @tc.name: Listener_OnAudioCaptureChange_WithCallback_001
 * @tc.desc: OnAudioCaptureChange forwards the capture change to the registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnAudioCaptureChange_WithCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    AudioRecorderChangeInfo info;
    stub_->OnAudioCaptureChange(info);
    EXPECT_EQ(1, cb->audioChangeCount_);
}

/**
 * @tc.name: Listener_OnAudioCaptureChange_NoCallback_001
 * @tc.desc: OnAudioCaptureChange is not delivered to a callback that has been unregistered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnAudioCaptureChange_NoCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->SetRecorderCallback(nullptr);

    AudioRecorderChangeInfo info;
    stub_->OnAudioCaptureChange(info);

    EXPECT_EQ(0, cb->audioChangeCount_);
}

/**
 * @tc.name: Listener_OnPhotoAssetAvailable_WithCallback_001
 * @tc.desc: OnPhotoAssetAvailable forwards the asset uri to the registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnPhotoAssetAvailable_WithCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->OnPhotoAssetAvailable("file://media/Photo/1");
    EXPECT_EQ(1, cb->photoCount_);
}

/**
 * @tc.name: Listener_OnPhotoAssetAvailable_NoCallback_001
 * @tc.desc: OnPhotoAssetAvailable is not delivered to a callback that has been unregistered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_OnPhotoAssetAvailable_NoCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->SetRecorderCallback(nullptr);

    stub_->OnPhotoAssetAvailable("file://media/Photo/2");

    EXPECT_EQ(0, cb->photoCount_);
}

/**
 * @tc.name: Listener_SetMonitor_Empty_001
 * @tc.desc: OnError still invokes the callback when no Monitor is set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderListenerStubTest, Listener_SetMonitor_Empty_001, TestSize.Level2)
{
    stub_->SetMonitor(std::weak_ptr<MonitorClientObject>());
    auto cb = std::make_shared<TestRecorderCallback>();
    stub_->SetRecorderCallback(cb);
    stub_->OnError(static_cast<int32_t>(RECORDER_ERROR_INTERNAL), 1003);
    EXPECT_EQ(1, cb->errorCount_);
}
} // namespace Media
} // namespace OHOS
