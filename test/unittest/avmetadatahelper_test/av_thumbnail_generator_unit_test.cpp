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
#include "av_thumbnail_generator.h"

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
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace Test {
void AVThumbnailGeneratorUnitTest::SetUpTestCase(void) {}

void AVThumbnailGeneratorUnitTest::TearDownTestCase(void) {}

void AVThumbnailGeneratorUnitTest::SetUp(void)
{
    std::shared_ptr<MediaDemuxer> mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    avthumbnailGenerator = std::make_shared<AVThumbnailGenerator>(mediaDemuxer_);
}

void AVThumbnailGeneratorUnitTest::TearDown(void)
{
    mediaDemuxer_ = nullptr;
    avthumbnailGenerator = nullptr;
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
    avthumbnailGenerator->OnInputBufferAvailable(index, buffer);
    avthumbnailGenerator->stopProcessing_ = true;
    avthumbnailGenerator->OnInputBufferAvailable(index, buffer);
    avthumbnailGenerator->hasFetchedFrame_ = true;
    avthumbnailGenerator->OnInputBufferAvailable(index, buffer);
    EXPECT_EQ(avthumbnailGenerator->seekTime_, 0);
}

/**
 * @tc.name: OnOutputBufferAvailable
 * @tc.desc: OnOutputBufferAvailable
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, OnOutputBufferAvailable, TestSize.Level1)
{
    uint32_t index = 0;
    std::string trackMime_ = "test";
    uint8_t data[100];
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
    avthumbnailGenerator->videoDecoder_ = MediaAVCodec::VideoDecoderFactory::CreateByMime(trackMime_);
    avthumbnailGenerator->OnOutputBufferAvailable(index, buffer);
    avthumbnailGenerator->hasFetchedFrame_ = true;
    avthumbnailGenerator->OnOutputBufferAvailable(index, buffer);
    avthumbnailGenerator->hasFetchedFrame_ = false;
    buffer->pts_ = -1;
    avthumbnailGenerator->OnOutputBufferAvailable(index, buffer);
    EXPECT_EQ(avthumbnailGenerator->trackIndex_, 0);
}

/**
 * @tc.name: GenerateAlignmentAvBuffer
 * @tc.desc: GenerateAlignmentAvBuffer
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, GenerateAlignmentAvBuffer, TestSize.Level1)
{
    uint8_t data[100];
    avthumbnailGenerator->avBuffer_ = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
    avthumbnailGenerator->GenerateAlignmentAvBuffer();
    avthumbnailGenerator->avBuffer_ = nullptr;
    avthumbnailGenerator->GenerateAlignmentAvBuffer();
    EXPECT_EQ(avthumbnailGenerator->trackIndex_, 0);
}

/**
 * @tc.name: Reset
 * @tc.desc: Reset
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, Reset, TestSize.Level1)
{
    std::string trackMime_ = "test";
    avthumbnailGenerator->Reset();
    avthumbnailGenerator->mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    avthumbnailGenerator->Reset();
    avthumbnailGenerator->videoDecoder_ = MediaAVCodec::VideoDecoderFactory::CreateByMime(trackMime_);
    avthumbnailGenerator->Reset();
    EXPECT_EQ(avthumbnailGenerator->trackIndex_, 0);
}

/**
 * @tc.name: CopySurfaceBufferInfo
 * @tc.desc: CopySurfaceBufferInfo
 * @tc.type: FUNC
 */
HWTEST_F(AVThumbnailGeneratorUnitTest, CopySurfaceBufferInfo, TestSize.Level1)
{
    sptr<SurfaceBuffer> source = nullptr;
    sptr<SurfaceBuffer> dst = nullptr;
    avthumbnailGenerator->CopySurfaceBufferInfo(source, dst);
    uint8_t data[100];
    avthumbnailGenerator->avBuffer_ = AVBuffer::CreateAVBuffer(data, sizeof(data), sizeof(data));
    source = avthumbnailGenerator->avBuffer_->memory_->GetSurfaceBuffer();
    dst = avthumbnailGenerator->avBuffer_->memory_->GetSurfaceBuffer();
    avthumbnailGenerator->CopySurfaceBufferInfo(source, dst);
    EXPECT_EQ(avthumbnailGenerator->trackIndex_, 0);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS