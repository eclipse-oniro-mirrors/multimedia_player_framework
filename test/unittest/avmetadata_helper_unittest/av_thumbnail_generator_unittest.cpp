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

#include "buffer/avbuffer_common.h"
#include "common/media_source.h"
#include "ibuffer_consumer_listener.h"
#include "graphic_common_c.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_description.h"
#include "meta/meta.h"
#include "meta/meta_key.h"
#include "plugin/plugin_time.h"
#include "sync_fence.h"
#include "uri_helper.h"

#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "v1_0/buffer_handle_meta_key_type.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
namespace Test {
static const int32_t NUM_TEST = 1000;
static const int64_t ERR_OK = 0;
void AVThumbnailGeneratorUnitTest::SetUpTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::TearDownTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::SetUp(void)
{
    avThumbnailGenerator_ = std::make_shared<AVThumbnailGenerator>(mediaDemuxer_);
    mockMediaDemuxer_ = std::make_shared<MockMediaDemuxer>();
    avThumbnailGenerator_->mediaDemuxer_ = mockMediaDemuxer_;
}
 
void AVThumbnailGeneratorUnitTest::TearDown(void)
{
    mockMediaDemuxer_ = nullptr;
    avThumbnailGenerator_ = nullptr;
}

/**
 * @tc.name: StopTask
 * @tc.desc: Test readTask_ != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, StopTask, TestSize.Level1)
{
    avThumbnailGenerator_->readTask_ = nullptr;
    auto ret = avThumbnailGenerator_->StopTask();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnError
 * @tc.desc: Test all
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnError, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    MediaAVCodec::AVCodecErrorType errorType = MediaAVCodec::AVCODEC_ERROR_EXTEND_START;
    int32_t errorCode = -1;
    avThumbnailGenerator_->OnError(errorType, errorCode);
    EXPECT_EQ(avThumbnailGenerator_->stopProcessing_, true);
}

/**
 * @tc.name: OnOutputFormatChanged
 * @tc.desc: Test all
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputFormatChanged, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    MediaAVCodec::Format format;
    avThumbnailGenerator_->OnOutputFormatChanged(format);
    EXPECT_EQ(avThumbnailGenerator_->width_, 0);
}

/**
 * @tc.name: OnInputBufferAvailable
 * @tc.desc: Test if (stopProcessing_.load() || hasFetchedFrame_.load() || readErrorFlag_.load())
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnInputBufferAvailable_003, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    uint32_t index = 0;
    auto mockBuffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->meta_ = std::make_shared<Meta>();
    std::shared_ptr<AVBuffer> buffer = mockBuffer;
    mockInputBufferQueueConsumer_ = new MockAVBufferQueueConsumer();
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockInputBufferQueueConsumer_;
    avThumbnailGenerator_->stopProcessing_ = true;
    avThumbnailGenerator_->hasFetchedFrame_ = true;
    avThumbnailGenerator_->readErrorFlag_ = true;
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
}

/**
 * @tc.name: OnOutputBufferAvailable
 * @tc.desc: Test if (!isValidBuffer || !isValidState)
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    uint32_t index = 0;
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    EXPECT_CALL(*(mockAVCodecVideoDecoder), ReleaseOutputBuffer(_,_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Stop()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Release()).WillRepeatedly(Return(0));
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;
    auto mockBuffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->flag_ = static_cast<uint32_t>(AVBufferFlag::EOS);
    auto mockMemory = std::make_shared<AVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> buffer = mockBuffer;
    avThumbnailGenerator_->stopProcessing_ = true;
    avThumbnailGenerator_->hasFetchedFrame_ = true;
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
}

/**
 * @tc.name: OnOutputBufferAvailable
 * @tc.desc: Test if (!isAvailableFrame)
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable_003, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    uint32_t index = 0;
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    EXPECT_CALL(*(mockAVCodecVideoDecoder), ReleaseOutputBuffer(_,_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Stop()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Release()).WillRepeatedly(Return(0));
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;
    auto mockBuffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->flag_ = static_cast<uint32_t>(AVBufferFlag::NONE);
    auto mockMemory = std::make_shared<AVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> buffer = mockBuffer;
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->seekMode_ = Plugins::SeekMode::SEEK_CLOSEST;
    buffer->pts_ = -1;
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
}

/**
 * @tc.name: OnOutputBufferAvailable
 * @tc.desc: Test if (isClosest && avBuffer_ != nullptr) && buffer->flag_ & (uint32_t)(AVBufferFlag::EOS)
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable_004, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    uint32_t index = 0;
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    EXPECT_CALL(*(mockAVCodecVideoDecoder), ReleaseOutputBuffer(_,_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Stop()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Release()).WillRepeatedly(Return(0));
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;
    auto mockBuffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->flag_ = static_cast<uint32_t>(AVBufferFlag::EOS);
    auto mockMemory = std::make_shared<AVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> buffer = mockBuffer;
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;

    avThumbnailGenerator_->seekMode_ = Plugins::SeekMode::SEEK_CLOSEST;
    auto mockBuffer2 = std::make_shared<AVBuffer>();
    avThumbnailGenerator_->avBuffer_ = mockBuffer2;
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
}

/**
 * @tc.name: OnOutputBufferAvailable
 * @tc.desc: Test buffer->flag_ != (uint32_t)(AVBufferFlag::EOS)
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable_005, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    uint32_t index = 0;
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    EXPECT_CALL(*(mockAVCodecVideoDecoder), ReleaseOutputBuffer(_,_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Stop()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Release()).WillRepeatedly(Return(0));
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;
    auto mockBuffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->flag_ = static_cast<uint32_t>(AVBufferFlag::NONE);
    auto mockMemory = std::make_shared<AVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> buffer = mockBuffer;
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;

    avThumbnailGenerator_->seekMode_ = Plugins::SeekMode::SEEK_CLOSEST;
    auto mockAVBuffer = std::make_shared<AVBuffer>();
    mockAVBuffer->pts_ = -1;
    avThumbnailGenerator_->avBuffer_ = mockAVBuffer;
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
}

/**
 * @tc.name: HandleFetchFrameYuvFailed
 * @tc.desc: Test all
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, HandleFetchFrameYuvFailed, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    EXPECT_CALL(*(mockMediaDemuxer_), Pause()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*(mockMediaDemuxer_), Flush()).WillRepeatedly(Return(Status::OK));
    avThumbnailGenerator_->readErrorFlag_ = false;
    avThumbnailGenerator_->stopProcessing_ = false;
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    EXPECT_CALL(*(mockAVCodecVideoDecoder), ReleaseOutputBuffer(_,_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Flush()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Stop()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), Release()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockAVCodecVideoDecoder), SetParameter(_)).WillRepeatedly(Return(0));
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;

    avThumbnailGenerator_->HandleFetchFrameYuvFailed();
    EXPECT_EQ(avThumbnailGenerator_->hasFetchedFrame_, true);
}

/**
 * @tc.name: SeekToTime
 * @tc.desc: Test option == Plugins::SeekMode::SEEK_CLOSEST
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, SeekToTime, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    int64_t timeMs = 0;
    Plugins::SeekMode option = Plugins::SeekMode::SEEK_CLOSEST;
    int64_t realSeekTime = 0;
    EXPECT_CALL(*(mockMediaDemuxer_), SeekTo(_,_,_)).WillRepeatedly(Return(Status::OK));
    auto ret = avThumbnailGenerator_->SeekToTime(timeMs, option, realSeekTime);
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name: GetYuvDataAlignStride
 * @tc.desc: Test outputHeight < height && format = GRAPHIC_PIXEL_FMT_YCBCR_P010
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, GetYuvDataAlignStride, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*(mockSurfaceBuffer), GetHeight()).WillRepeatedly(Return(NUM_TEST));
    EXPECT_CALL(*(mockSurfaceBuffer), GetFormat()).
        WillRepeatedly(Return(static_cast<int32_t>(GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010)));
    EXPECT_CALL(*(mockSurfaceBuffer), GetWidth()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockSurfaceBuffer), GetStride()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockSurfaceBuffer), GetVirAddr()).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*(mockSurfaceBuffer), GetSize()).WillRepeatedly(Return(0));
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    auto ret = avThumbnailGenerator_->GetYuvDataAlignStride(surfaceBuffer);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: GenerateAlignmentAvBuffer
 * @tc.desc: Test outputHeight < height
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, GenerateAlignmentAvBuffer, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*(mockSurfaceBuffer), GetWidth()).WillRepeatedly(Return(NUM_TEST));
    EXPECT_CALL(*(mockSurfaceBuffer), Alloc(_)).WillRepeatedly(Return(GSError::GSERROR_OK));
    EXPECT_CALL(*(mockSurfaceBuffer), GetHeight()).WillRepeatedly(Return(NUM_TEST));
    EXPECT_CALL(*(mockSurfaceBuffer), GetFormat()).
        WillRepeatedly(Return(static_cast<int32_t>(GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010)));
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    auto mockBuffer = std::make_shared<AVBuffer>();
    auto mockMemory = std::make_shared<AVMemory>();
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(mockSurfaceBuffer));
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(NUM_TEST));
    mockBuffer->memory_ = mockMemory;
    avThumbnailGenerator_->avBuffer_ = mockBuffer;
    auto ret = avThumbnailGenerator_->GenerateAlignmentAvBuffer();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: SetSbStaticMetadata
 * @tc.desc: Test SetMetadata return GSERROR_OK
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, SetSbStaticMetadata, TestSize.Level1)
{
    ASSERT_NE(avThumbnailGenerator_, nullptr);
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*(mockSurfaceBuffer), SetMetadata(_,_,_)).WillRepeatedly(Return(GSERROR_OK));
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    std::vector<uint8_t> dynamicMetadata;
    auto ret = avThumbnailGenerator_->SetSbStaticMetadata(surfaceBuffer, dynamicMetadata);
    EXPECT_EQ(ret, true);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS