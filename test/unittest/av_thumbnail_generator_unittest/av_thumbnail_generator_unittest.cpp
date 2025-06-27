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

#include "av_thumbnail_generator_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace MediaAVCodec;
static const int32_t NUM_0 = 0;

void AVThumbnailGeneratorUnitTest::SetUpTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::TearDownTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::SetUp(void)
{
    std::shared_ptr<MediaDemuxer> mediaDemuxer = nullptr;
    avThumbnailGenerator_ = std::make_shared<AVThumbnailGenerator>(mediaDemuxer, NUM_0, NUM_0, NUM_0, NUM_0);
}
 
void AVThumbnailGeneratorUnitTest::TearDown(void)
{
    avThumbnailGenerator_ = nullptr;
}

/**
 * @tc.name  : Test ThumnGeneratorCodecCallback::OnError
 * @tc.number: OnError_001
 * @tc.desc  : Test generator != nullptr
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnError_001, TestSize.Level0)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    auto callback = std::make_shared<ThumnGeneratorCodecCallback>(avThumbnailGenerator_);
    avThumbnailGenerator_->stopProcessing_ = false;
    callback->OnError(AVCodecErrorType::AVCODEC_ERROR_INTERNAL, NUM_0);
    EXPECT_EQ(avThumbnailGenerator_->stopProcessing_, true);
}

/**
 * @tc.name  : Test ThumnGeneratorCodecCallback::OnOutputFormatChanged
 * @tc.number: OnOutputFormatChanged_001
 * @tc.desc  : Test generator == nullptr
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputFormatChanged_001, TestSize.Level0)
{
    avThumbnailGenerator_ = nullptr;
    auto callback = std::make_shared<ThumnGeneratorCodecCallback>(avThumbnailGenerator_);
    Format format = Format();
    callback->OnOutputFormatChanged(format);
    EXPECT_EQ(callback->generator_.lock(), nullptr);
}

/**
 * @tc.name  : Test ThumnGeneratorCodecCallback::OnInputBufferAvailable
 * @tc.number: ThumnGeneratorCodecCallback_OnInputBufferAvailable_001
 * @tc.desc  : Test generator == nullptr
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, ThumnGeneratorCodecCallback_OnInputBufferAvailable_001, TestSize.Level0)
{
    avThumbnailGenerator_ = nullptr;
    auto callback = std::make_shared<ThumnGeneratorCodecCallback>(avThumbnailGenerator_);
    uint32_t index = NUM_0;
    shared_ptr<AVBuffer> buffer = nullptr;
    callback->OnInputBufferAvailable(index, buffer);
    EXPECT_EQ(callback->generator_.lock(), nullptr);
}

/**
 * @tc.name  : Test ThumnGeneratorCodecCallback::OnOutputBufferAvailable
 * @tc.number: OnOutputBufferAvailable_001
 * @tc.desc  : Test generator == nullptr
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable_001, TestSize.Level0)
{
    avThumbnailGenerator_ = nullptr;
    auto callback = std::make_shared<ThumnGeneratorCodecCallback>(avThumbnailGenerator_);
    uint32_t index = NUM_0;
    shared_ptr<AVBuffer> buffer = nullptr;
    callback->OnOutputBufferAvailable(index, buffer);
    EXPECT_EQ(callback->generator_.lock(), nullptr);
}

/**
 * @tc.name  : Test ThumbnailGeneratorAVBufferAvailableListener::OnBufferAvailable
 * @tc.number: OnBufferAvailable_001
 * @tc.desc  : Test generator == nullptr
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnBufferAvailable_001, TestSize.Level0)
{
    avThumbnailGenerator_ = nullptr;
    auto listener = std::make_shared<ThumbnailGeneratorAVBufferAvailableListener>(avThumbnailGenerator_);
    listener->OnBufferAvailable();
    EXPECT_EQ(listener->generator_.lock(), nullptr);
}

/**
 * @tc.name  : Test OnInputBufferAvailable
 * @tc.number: OnInputBufferAvailable_001
 * @tc.desc  : Test (stopProcessing_.load() || hasFetchedFrame_.load() || readErrorFlag_.load()) == true
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnInputBufferAvailable_001, TestSize.Level0)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    avThumbnailGenerator_->stopProcessing_ = true;
    sptr<Media::MockAVBufferQueueConsumer> mockAVBufferQueueConsumer =new MockAVBufferQueueConsumer();
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockAVBufferQueueConsumer;
    auto buffer = std::make_shared<AVBuffer>();
    buffer->meta_ = std::make_shared<Meta>();
    uint32_t index = NUM_0;
    EXPECT_CALL(*mockAVBufferQueueConsumer, IsBufferInQueue(_)).Times(0);
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
}
}  // namespace Media
}  // namespace OHOS