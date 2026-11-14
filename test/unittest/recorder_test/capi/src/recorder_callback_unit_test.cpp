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

#include "recorder_unit_test.h"
#include <atomic>
#include <mutex>
#include <vector>
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace {
struct StateObserver {
    std::mutex mutex;
    std::vector<OH_AVRecorder_State> states;
    std::atomic<int32_t> reentrantCalls { 0 };
    std::atomic<OH_AVErrCode> reentrantRet { AV_ERR_OK };
    bool doReentrantRelease = false;
};

void OnStateChangeObs(OH_AVRecorder *recorder, OH_AVRecorder_State state,
    OH_AVRecorder_StateChangeReason reason, void *userData)
{
    (void)reason;
    auto *obs = reinterpret_cast<StateObserver *>(userData);
    if (obs == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(obs->mutex);
        obs->states.push_back(state);
    }
    if (state == AVRECORDER_RELEASED && obs->doReentrantRelease && recorder != nullptr) {
        // Releasing again from the callback must be idempotent and must not deadlock
        obs->reentrantRet.store(OH_AVRecorder_Release(recorder));
        obs->reentrantCalls.fetch_add(1);
    }
}
} // namespace

/**
 * @tc.name: Recorder_Callback_ReleaseReportsReleased_001
 * @tc.desc: Release reports AVRECORDER_RELEASED synchronously, no other state is reported during release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Callback_ReleaseReportsReleased_001, TestSize.Level2)
{
    ASSERT_NE(recorder_, nullptr);
    StateObserver obs {};
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_SetStateCallback(recorder_, OnStateChangeObs, &obs));

    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder_));
    recorder_ = nullptr; // Already released; avoid double release in TearDown

    std::lock_guard<std::mutex> lock(obs.mutex);
    ASSERT_FALSE(obs.states.empty());
    EXPECT_EQ(AVRECORDER_RELEASED, obs.states.back());
    for (auto state : obs.states) {
        EXPECT_EQ(AVRECORDER_RELEASED, state);
    }
}

/**
 * @tc.name: Recorder_Callback_ReentrantReleaseInCallback_001
 * @tc.desc: Releasing again inside the release callback returns AV_ERR_OK without deadlock or double free
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Callback_ReentrantReleaseInCallback_001, TestSize.Level2)
{
    ASSERT_NE(recorder_, nullptr);
    StateObserver obs {};
    obs.doReentrantRelease = true;
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_SetStateCallback(recorder_, OnStateChangeObs, &obs));

    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder_));
    recorder_ = nullptr;

    EXPECT_EQ(1, obs.reentrantCalls.load());
    EXPECT_EQ(AV_ERR_OK, obs.reentrantRet.load());
}

/**
 * @tc.name: Recorder_Callback_StartWithoutPrepareReportsError_001
 * @tc.desc: Start without Prepare reports AVRECORDER_ERROR to the app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Callback_StartWithoutPrepareReportsError_001, TestSize.Level2)
{
    ASSERT_NE(recorder_, nullptr);
    StateObserver obs {};
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_SetStateCallback(recorder_, OnStateChangeObs, &obs));

    EXPECT_EQ(AV_ERR_INVALID_VAL, OH_AVRecorder_Start(recorder_));

    {
        std::lock_guard<std::mutex> lock(obs.mutex);
        ASSERT_FALSE(obs.states.empty());
        EXPECT_EQ(AVRECORDER_ERROR, obs.states.back());
    }

    // The callback keeps a pointer to the stack object, so release here to avoid use-after-free later
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder_));
    recorder_ = nullptr;
}

/**
 * @tc.name: Recorder_Callback_ReleaseWithoutCallback_001
 * @tc.desc: Release succeeds when the app registers no callback at all
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Callback_ReleaseWithoutCallback_001, TestSize.Level2)
{
    OH_AVRecorder *recorder = OH_AVRecorder_Create();
    ASSERT_NE(recorder, nullptr);
    // No state/error/uri callback is registered: release must not depend on them
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder));
}

/**
 * @tc.name: Recorder_Callback_ReleaseTwice_001
 * @tc.desc: Releasing an already released handle is idempotent and only looks the handle up in the registry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Callback_ReleaseTwice_001, TestSize.Level2)
{
    OH_AVRecorder *recorder = OH_AVRecorder_Create();
    ASSERT_NE(recorder, nullptr);
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder));

    // The second release hits the "already released" registry branch, no object is dereferenced
    EXPECT_EQ(AV_ERR_OK, OH_AVRecorder_Release(recorder));
}
