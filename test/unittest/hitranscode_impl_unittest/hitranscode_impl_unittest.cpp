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

#include "hitranscode_impl_unittest.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

const static int32_t TIMES_ONE = 1;
const static int32_t TIMES_TWO = 2;
const std::string MEDIA_ROOT = "files:///data/test/media/";

void HitranscodeImplUnitTest::SetUpTestCase(void)
{
}

void HitranscodeImplUnitTest::TearDownTestCase(void)
{
}

void HitranscodeImplUnitTest::SetUp(void)
{
    int32_t appUid = 0;
    int32_t appPid = 0;
    uint32_t appTokenId = 0;
    uint64_t appFullTokenId = 0;

    demuxerFilter_ = std::make_shared<Pipeline::DemuxerFilter>("mockDemuxerFilter",
        Pipeline::FilterType::FILTERTYPE_DEMUXER);
    mockCallbackLooper_ = std::make_shared<MockHiTransCoderCallbackLooper>();
    transcoder_ = std::make_unique<HiTransCoderImpl>(appUid, appPid, appTokenId, appFullTokenId);
}

void HitranscodeImplUnitTest::TearDown(void)
{
    demuxerFilter_.reset();
    mockCallbackLooper_.reset();
    transcoder_.reset();
}

/**
 * @tc.name  : Test SetInputFile
 * @tc.number: SetInputFile_001
 * @tc.desc  : Test SetInputFile demuxerFilter_ == nullptr
 *             Test ~HiTransCoderImpl transCoderEventReceiver_ == nullptr
 *             Test ~HiTransCoderImpl transCoderFilterCallback_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, SetInputFile_001, TestSize.Level1)
{
    // Test SetInputFile demuxerFilter_ == nullptr
    Pipeline::FilterFactory::Instance().generators.clear();

    // Test ~HiTransCoderImpl transCoderEventReceiver_ == nullptr
    transcoder_->transCoderEventReceiver_ = nullptr;

    // Test ~HiTransCoderImpl transCoderFilterCallback_ == nullptr
    transcoder_->transCoderFilterCallback_ = nullptr;

    int32_t ret = transcoder_->SetInputFile(MEDIA_ROOT);
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/**
 * @tc.name  : Test SetInputFile
 * @tc.number: SetInputFile_002
 * @tc.desc  : Test SetInputFile TransTranscoderStatus != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, SetInputFile_002, TestSize.Level1)
{
    Pipeline::FilterFactory::Instance().RegisterFilter<Pipeline::DemuxerFilter>(
        "builtin.player.demuxer", Pipeline::FilterType::FILTERTYPE_DEMUXER,
        [](const std::string& name, const Pipeline::FilterType type) {
            return std::make_shared<Pipeline::DemuxerFilter>(name, Pipeline::FilterType::FILTERTYPE_DEMUXER);
        }
    );
    int32_t ret = transcoder_->SetInputFile(MEDIA_ROOT);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_CONTAINER_TYPE);
}

/**
 * @tc.name  : Test ConfigureVideoAudioMetaData
 * @tc.number: ConfigureVideoAudioMetaData_001
 * @tc.desc  : Test ConfigureVideoAudioMetaData trackCount == 0
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoAudioMetaData_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    Status ret = transcoder_->ConfigureVideoAudioMetaData();
    EXPECT_EQ(ret, Status::ERROR_NO_TRACK);
}

/**
 * @tc.name  : Test Start
 * @tc.number: Start_001
 * @tc.desc  : Test Start TransTranscoderStatus(pipeline_->Start()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Start_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Start();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test Resume
 * @tc.number: Resume_001
 * @tc.desc  : Test Resume TransTranscoderStatus(pipeline_->Resume()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Resume_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Resume();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test Cancel
 * @tc.number: Cancel_001
 * @tc.desc  : Test Cancel TransTranscoderStatus(pipeline_->Stop()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Cancel_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCallbackLooper_, OnError(_, _)).Times(TIMES_ONE);
    transcoder_->callbackLooper_ = mockCallbackLooper_;

    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Cancel();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test HandleErrorEvent
 * @tc.number: HandleErrorEvent_001
 * @tc.desc  : Test HandleErrorEvent pipeline_ == nullptr
 *             Test OnEvent event.type == EventType::EVENT_COMPLETE
 *             Test OnEvent event.type == default
 */
HWTEST_F(HitranscodeImplUnitTest, HandleErrorEvent_001, TestSize.Level1)
{
    // Test OnEvent event.type == EventType::EVENT_COMPLETE
    Event event { .type = EventType::EVENT_COMPLETE };
    transcoder_->OnEvent(event);

    // Test OnEvent event.type == default
    event.type = EventType::EVENT_READY;
    transcoder_->OnEvent(event);

    // Test HandleErrorEvent pipeline_ == nullptr
    EXPECT_CALL(*mockCallbackLooper_, OnError(_, _)).Times(TIMES_ONE);
    transcoder_->ignoreError_ = false;
    transcoder_->callbackLooper_ = mockCallbackLooper_;
    transcoder_->pipeline_.reset();
    int32_t errorCode = MSERR_OK;
    transcoder_->HandleErrorEvent(errorCode);
}

/**
 * @tc.name  : Test HandleCompleteEvent
 * @tc.number: HandleCompleteEvent_001
 * @tc.desc  : Test HandleCompleteEvent obs_.lock() == nullptr
 *             Test HandleCompleteEvent pipeline_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, HandleCompleteEvent_001, TestSize.Level1)
{
    // Test HandleCompleteEvent obs_.lock() == nullptr
    transcoder_->obs_.reset();

    // Test HandleCompleteEvent pipeline_ == nullptr
    transcoder_->pipeline_.reset();

    transcoder_->callbackLooper_ = mockCallbackLooper_;
    transcoder_->HandleCompleteEvent();
    EXPECT_EQ(transcoder_->callbackLooper_->taskStarted_, false);
}

/**
 * @tc.name  : Test HandleCompleteEvent
 * @tc.number: HandleCompleteEvent_002
 * @tc.desc  : Test HandleCompleteEvent obs_.lock() != nullptr
 *             Test HandleCompleteEvent pipeline_ != nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, HandleCompleteEvent_002, TestSize.Level1)
{
    transcoder_->callbackLooper_ = mockCallbackLooper_;
    auto mockEngineObs = std::make_shared<MockITransCoderEngineObs>();
    EXPECT_CALL(*mockEngineObs, OnInfo(_, _)).Times(TIMES_TWO);
    transcoder_->obs_ = mockEngineObs;
    transcoder_->HandleCompleteEvent();
}
} // namespace Media
} // namespace OHOS