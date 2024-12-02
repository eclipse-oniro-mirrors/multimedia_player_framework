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
 * @tc.name: GetYuvDataAlignStride
 * @tc.desc: GetYuvDataAlignStride
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, GetYuvDataAlignStride, TestSize.Level1)
{
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    surfaceBuffer->SetSurfaceBufferWidth(100);
    surfaceBuffer->SetSurfaceBufferHeight(100);
    BufferHandle handle;
    handle.format = static_cast<int32_t>(GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010);
    uint64_t usage = 10;
    handle.usage = usage;
    handle.stride = 16;
    BufferHandle* ptrHandle = &handle;
    surfaceBuffer->SetBufferHandle(ptrHandle);

    Format format;
    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, 2);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, 2);
    avThumbnailGenerator_->outputFormat_ = format;

    EXPECT_EQ(avThumbnailGenerator_->GetYuvDataAlignStride(surfaceBuffer), 0);
    if (ptrHandle) {
        delete ptrHandle;
        ptrHandle = nullptr;
    }
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

}  // namespace Test
}  // namespace Media
}  // namespace OHOS