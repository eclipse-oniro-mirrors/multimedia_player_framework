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

#include "av_thumbnail_generator_unit_test.h"

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
void AVThumbnailGeneratorUnitTest::SetUpTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::TearDownTestCase(void) {}
 
void AVThumbnailGeneratorUnitTest::SetUp(void)
{
    avThumbnailGenerator_ = std::make_shared<AVThumbnailGenerator>(mediaDemuxer_, 0, 0, 0, 0);
    mockMediaDemuxer_ = std::make_shared<MockMediaDemuxer>();
    avThumbnailGenerator_->mediaDemuxer_ = mockMediaDemuxer_;
}
 
void AVThumbnailGeneratorUnitTest::TearDown(void)
{
    mockMediaDemuxer_ = nullptr;
    avThumbnailGenerator_ = nullptr;
}

/**
 * @tc.name: FetchFrameAtTime
 * @tc.desc: FetchFrameAtTime
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, FetchFrameAtTime, TestSize.Level1)
{
    avThumbnailGenerator_->videoDecoder_ = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    struct OutputConfiguration param = {-1, -1, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;

    std::shared_ptr<Meta> globalMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> videoMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> imageMeta = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> trackInfos;
    globalMeta->SetData(Tag::MEDIA_ALBUM, "media");
    globalMeta->SetData(Tag::MEDIA_ALBUM_ARTIST, "media_test");
    globalMeta->SetData(Tag::MEDIA_ARTIST, "元数据测试");
    globalMeta->SetData(Tag::MEDIA_AUTHOR, "");
    globalMeta->SetData(Tag::MEDIA_COMPOSER, "测试");
    globalMeta->SetData(Tag::MEDIA_DURATION, 10030000);
    globalMeta->SetData(Tag::MEDIA_GENRE, "Lyrical");
    globalMeta->SetData(Tag::MEDIA_HAS_AUDIO, true);
    globalMeta->SetData(Tag::MEDIA_HAS_VIDEO, true);
    globalMeta->SetData(Tag::MEDIA_TITLE, "test");
    globalMeta->SetData(Tag::MEDIA_TRACK_COUNT, "3");
    globalMeta->SetData(Tag::MEDIA_DATE, "2022");
    globalMeta->SetData(Tag::MEDIA_FILE_TYPE, Plugins::FileType::MP4);
 
    videoMeta->SetData(Tag::VIDEO_ROTATION, Plugins::VideoRotation::VIDEO_ROTATION_0);
    videoMeta->SetData(Tag::VIDEO_HEIGHT, "480");
    videoMeta->SetData(Tag::VIDEO_WIDTH, "720");
    videoMeta->SetData(Tag::MIME_TYPE, "video/mp4");
    imageMeta->SetData(Tag::MIME_TYPE, "image");
    trackInfos.push_back(videoMeta);
    trackInfos.push_back(imageMeta);
    trackInfos.push_back(nullptr);
 
    EXPECT_CALL(*mockMediaDemuxer_, GetGlobalMetaInfo()).WillRepeatedly(Return(globalMeta));
    EXPECT_CALL(*mockMediaDemuxer_, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    EXPECT_CALL(*mockMediaDemuxer_, SeekTo).WillRepeatedly(Return(Status::OK));
    EXPECT_TRUE(avThumbnailGenerator_->FetchFrameAtTime(timeUs, queryOption, param) == nullptr);
    EXPECT_TRUE(avThumbnailGenerator_->FetchFrameYuv(timeUs, queryOption, param) == nullptr);

    uint32_t index = 0;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::ERROR_UNKNOWN));
    auto result = avThumbnailGenerator_->FetchFrameAtTime(timeUs, queryOption, param);
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(result == nullptr);
    auto ret = avThumbnailGenerator_->FetchFrameYuv(timeUs, queryOption, param);
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(ret == nullptr);
}

/**
 * @tc.name: OnInputBufferAvailable
 * @tc.desc: OnInputBufferAvailable
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnInputBufferAvailable, TestSize.Level1)
{
    uint32_t index = 0;
    std::shared_ptr<AVBuffer> buffer = nullptr;
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->readErrorFlag_ = true;
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(buffer == nullptr);

    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(buffer == nullptr);

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::END_OF_STREAM));
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(buffer == nullptr);

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::ERROR_AGAIN));
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(buffer == nullptr);
}

/**
 * @tc.name: OnInputBufferAvailable_001
 * @tc.desc: OnInputBufferAvailable_001
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnInputBufferAvailable_001, TestSize.Level1)
{
    uint32_t index = 0;
    uint8_t data[100];
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->readErrorFlag_ = false;
    avThumbnailGenerator_->isBufferAvailable_ = false;
    
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(buffer != nullptr);

    mockInputBufferQueueConsumer_ = new MockAVBufferQueueConsumer();
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockInputBufferQueueConsumer_;

    EXPECT_CALL(*(mockInputBufferQueueConsumer_),
                IsBufferInQueue(buffer)).WillRepeatedly(Return(false));
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(avThumbnailGenerator_->isBufferAvailable_);
}

/**
 * @tc.name: OnInputBufferAvailable_002
 * @tc.desc: OnInputBufferAvailable_002
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnInputBufferAvailable_002, TestSize.Level1)
{
    uint32_t index = 0;
    uint8_t data[100];
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->readErrorFlag_ = false;
    avThumbnailGenerator_->isBufferAvailable_ = false;

    mockInputBufferQueueConsumer_ = new MockAVBufferQueueConsumer();
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockInputBufferQueueConsumer_;

    EXPECT_CALL(*(mockInputBufferQueueConsumer_),
                IsBufferInQueue(buffer)).WillRepeatedly(Return(true));
    EXPECT_CALL(*(mockInputBufferQueueConsumer_),
                ReleaseBuffer(buffer)).WillRepeatedly(Return(Status::OK));
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(avThumbnailGenerator_->isBufferAvailable_);

    avThumbnailGenerator_->isBufferAvailable_ = false;
    EXPECT_CALL(*(mockInputBufferQueueConsumer_),
                ReleaseBuffer(buffer)).WillRepeatedly(Return(Status::ERROR_UNKNOWN));
    avThumbnailGenerator_->OnInputBufferAvailable(index, buffer);
    EXPECT_TRUE(!avThumbnailGenerator_->isBufferAvailable_);
}

/**
 * @tc.name: AcquireAvailableInputBuffer
 * @tc.desc: AcquireAvailableInputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, AcquireAvailableInputBuffer, TestSize.Level1)
{
    mockInputBufferQueueConsumer_ = new MockAVBufferQueueConsumer();
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockInputBufferQueueConsumer_;

    EXPECT_CALL(*(mockInputBufferQueueConsumer_),
                AcquireBuffer(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    avThumbnailGenerator_->AcquireAvailableInputBuffer();
    
    EXPECT_CALL(*(mockInputBufferQueueConsumer_), AcquireBuffer(_))
                .WillOnce(Invoke([] (std::shared_ptr<AVBuffer>& buffer) {
                    uint32_t index = 0;
                    uint8_t data[100];
                    buffer = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
                    buffer->meta_->SetData(Tag::BUFFER_INDEX, index);
                    return Status::OK;
                }));
    auto mockAVCodecVideoDecoder = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    avThumbnailGenerator_->videoDecoder_ = mockAVCodecVideoDecoder;
    EXPECT_CALL(*(mockAVCodecVideoDecoder),
                QueueInputBuffer(_)).WillRepeatedly(Return(-1));
    avThumbnailGenerator_->AcquireAvailableInputBuffer();

    auto res = avThumbnailGenerator_->Init();
    EXPECT_TRUE(res == MSERR_OK);
}

/**
 * @tc.name: Init_001
 * @tc.desc: Init_001
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, Init_001, TestSize.Level1)
{
    mockInputBufferQueue_ = std::make_shared<MockAVBufferQueue>();
    avThumbnailGenerator_->inputBufferQueue_ = mockInputBufferQueue_;

    EXPECT_CALL(*(mockInputBufferQueue_),
                GetQueueSize()).WillRepeatedly(Return(1));
    
    auto res = avThumbnailGenerator_->Init();
    EXPECT_TRUE(res == MSERR_OK);
}

/**
 * @tc.name: Init_001
 * @tc.desc: Init_001
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, Init_002, TestSize.Level1)
{
    mockInputBufferQueue_ = std::make_shared<MockAVBufferQueue>();
    auto res = avThumbnailGenerator_->Init();
    EXPECT_TRUE(res == MSERR_OK);
    res = avThumbnailGenerator_->Init();
    EXPECT_TRUE(res == MSERR_OK);
}

/**
 * @tc.name: ReadLoop
 * @tc.desc: ReadLoop
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, ReadLoop, TestSize.Level1)
{
    avThumbnailGenerator_->stopProcessing_ = false;
    avThumbnailGenerator_->hasFetchedFrame_ = false;
    avThumbnailGenerator_->readErrorFlag_ = false;
    avThumbnailGenerator_->isBufferAvailable_ = true;

    mockInputBufferQueueProducer_ = new MockAVBufferQueueProducer();
    avThumbnailGenerator_->inputBufferQueueProducer_ = mockInputBufferQueueProducer_;

    EXPECT_CALL(*(mockInputBufferQueueProducer_),
                RequestBuffer(_, _, _)).WillRepeatedly(Return(Status::ERROR_UNKNOWN));
    avThumbnailGenerator_->ReadLoop();
    EXPECT_TRUE(!avThumbnailGenerator_->isBufferAvailable_);

    avThumbnailGenerator_->isBufferAvailable_ = true;
    EXPECT_CALL(*(mockInputBufferQueueProducer_),
                RequestBuffer(_, _, _)).WillRepeatedly(Return(Status::OK));

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::OK));
    avThumbnailGenerator_->ReadLoop();
    EXPECT_TRUE(!avThumbnailGenerator_->readErrorFlag_);

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::END_OF_STREAM));
    avThumbnailGenerator_->ReadLoop();
    EXPECT_TRUE(!avThumbnailGenerator_->readErrorFlag_);

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::ERROR_AGAIN));
    avThumbnailGenerator_->ReadLoop();
    EXPECT_TRUE(!avThumbnailGenerator_->readErrorFlag_);

    EXPECT_CALL(*mockMediaDemuxer_, ReadSample).WillRepeatedly(Return(Status::ERROR_UNKNOWN));
    avThumbnailGenerator_->ReadLoop();
    EXPECT_TRUE(avThumbnailGenerator_->readErrorFlag_);
}

/**
 * @tc.name: Reset
 * @tc.desc: Reset
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, Reset, TestSize.Level1)
{
    avThumbnailGenerator_->mediaDemuxer_ = nullptr;
    avThumbnailGenerator_->videoDecoder_ = std::make_shared<MediaAVCodec::MockAVCodecVideoDecoder>();
    avThumbnailGenerator_->hasFetchedFrame_ = true;
    avThumbnailGenerator_->Reset();
    EXPECT_EQ(avThumbnailGenerator_->hasFetchedFrame_, false);
}

/**
 * @tc.name: CopySurfaceBufferInfo
 * @tc.desc: CopySurfaceBufferInfo
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, CopySurfaceBufferInfo, TestSize.Level1)
{
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> surfaceBuffer1 = nullptr;
    avThumbnailGenerator_->CopySurfaceBufferInfo(surfaceBuffer, surfaceBuffer1);
    EXPECT_EQ(surfaceBuffer1, nullptr);
    avThumbnailGenerator_->CopySurfaceBufferInfo(surfaceBuffer1, surfaceBuffer);
    EXPECT_EQ(surfaceBuffer1, nullptr);
    avThumbnailGenerator_->CopySurfaceBufferInfo(surfaceBuffer1, surfaceBuffer1);
    EXPECT_EQ(surfaceBuffer1, nullptr);
}

/**
 * @tc.name: AcquireAvailableInputBuffer_AVI
 * @tc.desc: AcquireAvailableInputBuffer_AVI
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, AcquireAvailableInputBuffer_AVI, TestSize.Level1)
{
    mockInputBufferQueueConsumer_ = new MockAVBufferQueueConsumer();
    EXPECT_CALL(*mockInputBufferQueueConsumer_, AcquireBuffer(_))
        .WillOnce([](std::shared_ptr<AVBuffer>& outBuffer) {
            outBuffer = std::make_shared<AVBuffer>();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return Status::OK;
        });
    avThumbnailGenerator_->inputBufferQueueConsumer_ = mockInputBufferQueueConsumer_;
    avThumbnailGenerator_->videoDecoder_ = nullptr;
    avThumbnailGenerator_->AcquireAvailableInputBuffer();
    EXPECT_EQ(avThumbnailGenerator_->fileType_, FileType::UNKNOW);
    avThumbnailGenerator_->fileType_ = FileType::AVI;
    EXPECT_CALL(*mockInputBufferQueueConsumer_, AcquireBuffer(_))
        .WillOnce([](std::shared_ptr<AVBuffer>& outBuffer) {
            outBuffer = std::make_shared<AVBuffer>();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return Status::OK;
        });
    avThumbnailGenerator_->AcquireAvailableInputBuffer();
    EXPECT_EQ(avThumbnailGenerator_->inputBufferDtsQue_.empty(), false);
}

/**
 * @tc.name: OnOutputBufferAvailable_AVI
 * @tc.desc: OnOutputBufferAvailable_AVI
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable_AVI, TestSize.Level1)
{
    uint32_t index = 1;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 10;
    buffer->dts_ = 20;
    ASSERT_NE(nullptr, buffer);
    avThumbnailGenerator_->videoDecoder_ = nullptr;
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
    EXPECT_EQ(avThumbnailGenerator_->fileType_, FileType::UNKNOW);
    avThumbnailGenerator_->fileType_ = FileType::AVI;
    ASSERT_NE(nullptr, buffer);
    EXPECT_EQ(avThumbnailGenerator_->inputBufferDtsQue_.empty(), true);
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
    EXPECT_EQ(buffer->pts_, buffer->dts_);
    int64_t dts = 11;
    avThumbnailGenerator_->inputBufferDtsQue_.push_back(dts);
    EXPECT_EQ(avThumbnailGenerator_->inputBufferDtsQue_.empty(), false);
    ASSERT_NE(nullptr, buffer);
    avThumbnailGenerator_->OnOutputBufferAvailable(index, buffer);
    EXPECT_EQ(buffer->pts_, dts);

    EXPECT_EQ(avThumbnailGenerator_->inputBufferQueueConsumer_, nullptr);
    avThumbnailGenerator_->FlushBufferQueue();
    EXPECT_EQ(avThumbnailGenerator_->inputBufferDtsQue_.empty(), true);
    int64_t dtss = 22;
    avThumbnailGenerator_->inputBufferDtsQue_.push_back(dtss);
    avThumbnailGenerator_->FlushBufferQueue();
    EXPECT_EQ(avThumbnailGenerator_->inputBufferDtsQue_.empty(), true);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS