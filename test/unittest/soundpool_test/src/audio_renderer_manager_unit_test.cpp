/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <climits>
#include <memory>

#include "audio_renderer_manager_unit_test.h"
#include "media_errors.h"
#include "media_log.h"
#include "mock_audio_renderer.h"
#include "parallel_stream_manager.h"
#include "stream_id_manager.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;
using namespace std;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "AudioRendererManagerUnitTest"};
constexpr int32_t AUDIO_RENDERER_MAX_NUM = 20;
}

namespace OHOS {
namespace Media {
void AudioRendererManagerUnitTest::SetUpTestCase(void)
{}

void AudioRendererManagerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect AudioRendererManager safely exit." << endl;
    sleep(1);
}

void AudioRendererManagerUnitTest::SetUp(void)
{
    manager_ = &AudioRendererManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager_->renderMgrMutex_);
    manager_->audioRendererVector_.clear();
    manager_->parallelManagerList_.clear();
    manager_->streamIDManagerList_.clear();
    manager_->globalIdNext_ = 0;
}

void AudioRendererManagerUnitTest::TearDown(void)
{
    std::lock_guard<std::mutex> lock(manager_->renderMgrMutex_);
    manager_->audioRendererVector_.clear();
    manager_->parallelManagerList_.clear();
    manager_->streamIDManagerList_.clear();
    manager_->globalIdNext_ = 0;
}

/**
 * @tc.name: audioRendererManager_function_001
 * @tc.desc: function test GetGlobalId increases and wraps around
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_001, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_001 before");
    EXPECT_EQ(1, manager_->GetGlobalId());
    EXPECT_EQ(2, manager_->GetGlobalId());
    manager_->globalIdNext_ = INT32_MAX;
    EXPECT_EQ(1, manager_->GetGlobalId());
    MEDIA_LOGI("audioRendererManager_function_001 after");
}

/**
 * @tc.name: audioRendererManager_function_002
 * @tc.desc: function test GetAudioRendererInstance with empty manager and nonexistent globalId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_002, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_002 before");
    EXPECT_EQ(nullptr, manager_->GetAudioRendererInstance(1));

    manager_->SetAudioRendererInstance(2, std::make_unique<NiceMock<MockAudioRenderer>>());
    EXPECT_EQ(1, manager_->audioRendererVector_.size());
    EXPECT_EQ(nullptr, manager_->GetAudioRendererInstance(1));
    EXPECT_EQ(1, manager_->audioRendererVector_.size());
    MEDIA_LOGI("audioRendererManager_function_002 after");
}

/**
 * @tc.name: audioRendererManager_function_003
 * @tc.desc: function test SetAudioRendererInstance and GetAudioRendererInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_003, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_003 before");
    auto audioRenderer = std::make_unique<NiceMock<MockAudioRenderer>>();
    MockAudioRenderer *audioRendererPtr = audioRenderer.get();
    manager_->SetAudioRendererInstance(5, std::move(audioRenderer));
    EXPECT_EQ(1, manager_->audioRendererVector_.size());

    std::unique_ptr<AudioStandard::AudioRenderer> findInstance = manager_->GetAudioRendererInstance(5);
    EXPECT_EQ(audioRendererPtr, findInstance.get());
    EXPECT_TRUE(manager_->audioRendererVector_.empty());
    MEDIA_LOGI("audioRendererManager_function_003 after");
}

/**
 * @tc.name: audioRendererManager_function_004
 * @tc.desc: function test SetAudioRendererInstance reaches max num without releasing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_004, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_004 before");
    for (int32_t i = 1; i <= AUDIO_RENDERER_MAX_NUM; ++i) {
        manager_->SetAudioRendererInstance(i, std::make_unique<StrictMock<MockAudioRenderer>>());
    }
    EXPECT_EQ(AUDIO_RENDERER_MAX_NUM, manager_->audioRendererVector_.size());
    MEDIA_LOGI("audioRendererManager_function_004 after");
}

/**
 * @tc.name: audioRendererManager_function_005
 * @tc.desc: function test SetAudioRendererInstance releases the oldest renderer when exceeding max num
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_005, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_005 before");
    auto oldestRenderer = std::make_unique<NiceMock<MockAudioRenderer>>();
    MockAudioRenderer *oldestRendererPtr = oldestRenderer.get();
    EXPECT_CALL(*oldestRendererPtr, Release()).WillOnce(Return(true));
    manager_->SetAudioRendererInstance(1, std::move(oldestRenderer));
    for (int32_t i = 2; i <= AUDIO_RENDERER_MAX_NUM; ++i) {
        manager_->SetAudioRendererInstance(i, std::make_unique<NiceMock<MockAudioRenderer>>());
    }
    manager_->SetAudioRendererInstance(AUDIO_RENDERER_MAX_NUM + 1,
        std::make_unique<NiceMock<MockAudioRenderer>>());
    EXPECT_EQ(AUDIO_RENDERER_MAX_NUM, manager_->audioRendererVector_.size());
    EXPECT_EQ(2, manager_->audioRendererVector_.front().first);
    MEDIA_LOGI("audioRendererManager_function_005 after");
}

/**
 * @tc.name: audioRendererManager_function_006
 * @tc.desc: function test RemoveOldAudioRenderer with empty manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_006, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_006 before");
    manager_->RemoveOldAudioRenderer();
    EXPECT_TRUE(manager_->audioRendererVector_.empty());
    MEDIA_LOGI("audioRendererManager_function_006 after");
}

/**
 * @tc.name: audioRendererManager_function_007
 * @tc.desc: function test RemoveOldAudioRenderer releases the oldest renderer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_007, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_007 before");
    auto audioRenderer = std::make_unique<NiceMock<MockAudioRenderer>>();
    MockAudioRenderer *audioRendererPtr = audioRenderer.get();
    EXPECT_CALL(*audioRendererPtr, Release()).WillOnce(Return(true));
    manager_->SetAudioRendererInstance(3, std::move(audioRenderer));
    manager_->RemoveOldAudioRenderer();
    EXPECT_TRUE(manager_->audioRendererVector_.empty());
    MEDIA_LOGI("audioRendererManager_function_007 after");
}

/**
 * @tc.name: audioRendererManager_function_008
 * @tc.desc: function test DelAudioRenderer with nonexistent and existing globalId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_008, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_008 before");
    auto audioRenderer = std::make_unique<NiceMock<MockAudioRenderer>>();
    MockAudioRenderer *audioRendererPtr = audioRenderer.get();
    EXPECT_CALL(*audioRendererPtr, Release()).WillOnce(Return(true));
    manager_->SetAudioRendererInstance(4, std::move(audioRenderer));

    manager_->DelAudioRenderer(99);
    EXPECT_EQ(1, manager_->audioRendererVector_.size());
    manager_->DelAudioRenderer(4);
    EXPECT_TRUE(manager_->audioRendererVector_.empty());
    MEDIA_LOGI("audioRendererManager_function_008 after");
}

/**
 * @tc.name: audioRendererManager_function_009
 * @tc.desc: function test SetParallelManager and SetStreamIDManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_009, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_009 before");
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    std::shared_ptr<ParallelStreamManager> parallelManager =
        std::make_shared<ParallelStreamManager>(1, audioRendererInfo);
    std::shared_ptr<IStreamIDManager> streamIDManager =
        std::make_shared<StreamIDManagerWithSameSoundInterrupt>(1, audioRendererInfo);

    manager_->SetParallelManager(parallelManager);
    manager_->SetStreamIDManager(streamIDManager);
    EXPECT_EQ(1, manager_->parallelManagerList_.size());
    EXPECT_EQ(1, manager_->streamIDManagerList_.size());
    EXPECT_EQ(parallelManager, manager_->parallelManagerList_.front().lock());
    EXPECT_EQ(streamIDManager, manager_->streamIDManagerList_.front().lock());
    MEDIA_LOGI("audioRendererManager_function_009 after");
}

/**
 * @tc.name: audioRendererManager_function_010
 * @tc.desc: function test DeleteManager deletes globalId from parallel managers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_010, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_010 before");
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    std::shared_ptr<ParallelStreamManager> parallelManager =
        std::make_shared<ParallelStreamManager>(1, audioRendererInfo);
    parallelManager->SetGlobalId(1, 100);
    parallelManager->SetGlobalId(2, 200);
    manager_->SetParallelManager(parallelManager);

    manager_->DeleteManager(100);
    EXPECT_EQ(1, parallelManager->globalIdVector_.size());
    EXPECT_EQ(200, parallelManager->globalIdVector_.front().second);
    MEDIA_LOGI("audioRendererManager_function_010 after");
}

/**
 * @tc.name: audioRendererManager_function_011
 * @tc.desc: function test DeleteManager with expired parallel manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioRendererManagerUnitTest, audioRendererManager_function_011, TestSize.Level2)
{
    MEDIA_LOGI("audioRendererManager_function_011 before");
    {
        AudioStandard::AudioRendererInfo audioRendererInfo;
        std::shared_ptr<ParallelStreamManager> parallelManager =
            std::make_shared<ParallelStreamManager>(1, audioRendererInfo);
        manager_->SetParallelManager(parallelManager);
    }
    manager_->DeleteManager(1);
    EXPECT_EQ(1, manager_->parallelManagerList_.size());
    EXPECT_EQ(nullptr, manager_->parallelManagerList_.front().lock());
    MEDIA_LOGI("audioRendererManager_function_011 after");
}

}  // namespace Media
}  // namespace OHOS
