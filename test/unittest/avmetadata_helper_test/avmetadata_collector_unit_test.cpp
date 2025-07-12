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
 
#include <string>
 
#include "avmetadata_collector_unit_test.h"
#include "avmetadatahelper.h"
#include "buffer/avsharedmemorybase.h"
#include "media_log.h"
#include "meta/video_types.h"
#include "meta/any.h"
#include "time_format_utils.h"
 
 
using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
namespace Test {
void AVMetaDataCollectorUnitTest::SetUpTestCase(void) {}
 
void AVMetaDataCollectorUnitTest::TearDownTestCase(void) {}
 
void AVMetaDataCollectorUnitTest::SetUp(void)
{
    avmetaDataCollector = std::make_shared<AVMetaDataCollector>(mediaDemuxer_);
    mediaDemuxer = std::make_shared<MockMediaDemuxer>();
    avmetaDataCollector->mediaDemuxer_ = mediaDemuxer;
}
 
void AVMetaDataCollectorUnitTest::TearDown(void)
{
    avmetaDataCollector->Destroy();
    avmetaDataCollector = nullptr;
    mediaDemuxer = nullptr;
}
 
/**
 * @tc.name: ExtractMetadata
 * @tc.desc: ExtractMetadata
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, ExtractMetadata, TestSize.Level1)
{
    std::shared_ptr<Meta> globalMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> videoMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> imageMeta = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> trackInfos;
    EXPECT_CALL(*mediaDemuxer, GetGlobalMetaInfo()).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    EXPECT_TRUE(avmetaDataCollector->ExtractMetadata().size() == 0);
 
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
 
    EXPECT_CALL(*mediaDemuxer, GetGlobalMetaInfo()).WillRepeatedly(Return(globalMeta));
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    avmetaDataCollector->ExtractMetadata();
    EXPECT_TRUE(avmetaDataCollector->collectedMeta_.size() != 0);
    avmetaDataCollector->ExtractMetadata();
    EXPECT_TRUE(avmetaDataCollector->collectedMeta_.size() != 0);
}
 
/**
 * @tc.name: GetAVMetadata
 * @tc.desc: GetAVMetadata
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_LOCATION_LATITUDE, "test"},
        {AV_KEY_LOCATION_LONGITUDE, "test"},
        {AV_KEY_VIDEO_IS_HDR_VIVID, "yes"},
        {10086, "test"},
    };
    std::shared_ptr<Meta> customerInfo = std::make_shared<Meta>();
    EXPECT_CALL(*mediaDemuxer, GetUserMeta()).WillRepeatedly(Return(nullptr));
    EXPECT_TRUE(avmetaDataCollector->GetAVMetadata() != nullptr);
 
    avmetaDataCollector->collectedAVMetaData_ = nullptr;
    avmetaDataCollector->collectedMeta_[AV_KEY_VIDEO_IS_HDR_VIVID] = "";
    EXPECT_CALL(*mediaDemuxer, GetUserMeta()).WillRepeatedly(Return(customerInfo));
    EXPECT_TRUE(avmetaDataCollector->GetAVMetadata() != nullptr);
    EXPECT_CALL(*mediaDemuxer, GetUserMeta()).WillRepeatedly(Return(customerInfo));
    EXPECT_TRUE(avmetaDataCollector->GetAVMetadata() != nullptr);
 
    EXPECT_CALL(*mediaDemuxer, Reset());
    avmetaDataCollector->Reset();
    EXPECT_TRUE(avmetaDataCollector->collectedMeta_.size() == 0);
}
 
/**
 * @tc.name: GetArtPicture
 * @tc.desc: GetArtPicture
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetArtPicture, TestSize.Level1)
{
    std::shared_ptr<Meta> videoMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> imageMeta = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> trackInfos;
    std::vector<uint8_t> coverAddr;
    trackInfos.push_back(nullptr);
    coverAddr.push_back(1);
    videoMeta->SetData(Tag::MIME_TYPE, "video/mp4");
    videoMeta->SetData(Tag::MEDIA_COVER, coverAddr);
    imageMeta->SetData(Tag::MIME_TYPE, "image");
    trackInfos.push_back(videoMeta);
    trackInfos.push_back(imageMeta);
 
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillOnce(Return(trackInfos));
    EXPECT_TRUE(avmetaDataCollector->GetArtPicture() != nullptr);
    EXPECT_TRUE(avmetaDataCollector->GetArtPicture() != nullptr);
}
 
/**
 * @tc.name: ExtractMetadataByKey
 * @tc.desc: ExtractMetadataByKey
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, ExtractMetadataByKey, TestSize.Level1)
{
    avmetaDataCollector->collectedAVMetaData_ = {};
    avmetaDataCollector->collectedMeta_ = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_ALBUM_ARTIST, ""},
    };
    
    std::string value = avmetaDataCollector->ExtractMetadata(AV_KEY_ALBUM);
    EXPECT_EQ(value, "media");
    value = avmetaDataCollector->ExtractMetadata(-1);
    EXPECT_EQ(value, "");
    value = avmetaDataCollector->ExtractMetadata(AV_KEY_ALBUM_ARTIST);
    EXPECT_EQ(value, "");
 
    avmetaDataCollector->collectedMeta_.clear();
    value = avmetaDataCollector->ExtractMetadata(AV_KEY_ALBUM);
    EXPECT_EQ(value, "");
}
 
/**
 * @tc.name: GetVideoTrackId
 * @tc.desc: GetVideoTrackId
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackId, TestSize.Level1)
{
    uint32_t trackId = 0;
    std::vector<std::shared_ptr<Meta>> trackInfos;
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    Status ret = avmetaDataCollector->GetVideoTrackId(trackId);
    EXPECT_EQ(ret, Status::ERROR_INVALID_DATA);
 
    std::shared_ptr<Meta> imageMeta = std::make_shared<Meta>();
    imageMeta->SetData(Tag::MIME_TYPE, "image");
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    imageMeta->SetData(Tag::MIME_TYPE, "image");
    trackInfos.push_back(imageMeta);
    trackInfos.push_back(meta);
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    ret = avmetaDataCollector->GetVideoTrackId(trackId);
    EXPECT_EQ(ret, Status::ERROR_INVALID_DATA);
 
    std::shared_ptr<Meta> videoMeta = std::make_shared<Meta>();
    videoMeta->SetData(Tag::MIME_TYPE, "video/mp4");
    trackInfos.push_back(videoMeta);
    EXPECT_CALL(*mediaDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(trackInfos));
    ret = avmetaDataCollector->GetVideoTrackId(trackId);
    EXPECT_EQ(ret, Status::OK);
}
 
/**
 * @tc.name: GetTimeByFrameIndex
 * @tc.desc: GetTimeByFrameIndex
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetTimeByFrameIndex, TestSize.Level1)
{
    uint32_t index = 0;
    uint64_t timeUs = 0;
    int32_t ret = avmetaDataCollector->GetTimeByFrameIndex(index, timeUs);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_FILE);
    avmetaDataCollector->hasVideo_ = true;
    avmetaDataCollector->videoTrackId_ = 0;
    EXPECT_CALL(*mediaDemuxer, GetRelativePresentationTimeUsByIndex(_, _, _))
                .WillRepeatedly(Return(Status::ERROR_INVALID_DATA));
    ret = avmetaDataCollector->GetTimeByFrameIndex(index, timeUs);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_FILE);
    EXPECT_CALL(*mediaDemuxer, GetRelativePresentationTimeUsByIndex(_, _, _)).WillRepeatedly(Return(Status::OK));
    ret = avmetaDataCollector->GetTimeByFrameIndex(index, timeUs);
    EXPECT_EQ(ret, MSERR_OK);
}
 
/**
 * @tc.name: GetFrameIndexByTime
 * @tc.desc: GetFrameIndexByTime
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetFrameIndexByTime, TestSize.Level1)
{
    uint32_t index = 0;
    uint64_t timeUs = 0;
    int32_t ret = avmetaDataCollector->GetFrameIndexByTime(timeUs, index);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_FILE);
    avmetaDataCollector->hasVideo_ = true;
    avmetaDataCollector->videoTrackId_ = 0;
    EXPECT_CALL(*mediaDemuxer, GetIndexByRelativePresentationTimeUs(_, _, _))
                .WillRepeatedly(Return(Status::ERROR_INVALID_DATA));
    ret = avmetaDataCollector->GetFrameIndexByTime(timeUs, index);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_FILE);
    EXPECT_CALL(*mediaDemuxer, GetIndexByRelativePresentationTimeUs(_, _, _)).WillRepeatedly(Return(Status::OK));
    ret = avmetaDataCollector->GetFrameIndexByTime(timeUs, index);
    EXPECT_EQ(ret, MSERR_OK);
}
 
/**
 * @tc.name: FormatMimeType
 * @tc.desc: FormatMimeType
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatMimeType, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    globalInfo->SetData(Tag::MEDIA_FILE_TYPE, Plugins::FileType::UNKNOW);
    avmetaDataCollector->FormatMimeType(avmeta, globalInfo);
    EXPECT_FALSE(avmeta.HasMeta(AV_KEY_MIME_TYPE));

    globalInfo->SetData(Tag::MEDIA_FILE_TYPE, "test");

    avmetaDataCollector->FormatMimeType(avmeta, globalInfo);
    EXPECT_FALSE(avmeta.HasMeta(AV_KEY_MIME_TYPE));

    avmeta.SetMeta(AV_KEY_HAS_AUDIO, "");
    globalInfo->SetData(Tag::MEDIA_FILE_TYPE, Plugins::FileType::MP4);
    avmetaDataCollector->FormatMimeType(avmeta, globalInfo);
    EXPECT_FALSE(avmeta.HasMeta(AV_KEY_MIME_TYPE));
}
 
/**
 * @tc.name: FormatDateTime
 * @tc.desc: FormatDateTime
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, "2022");
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    EXPECT_TRUE(avmeta.HasMeta(AV_KEY_DATE_TIME));
}
 
/**
 * @tc.name: ConvertToAVMeta
 * @tc.desc: ConvertToAVMeta
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, ConvertToAVMeta, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_ALBUM, "media");
    meta->SetData(Tag::MEDIA_ALBUM_ARTIST, "media_test");
    meta->SetData(Tag::MEDIA_ARTIST, "元数据测试");
    meta->SetData(Tag::MEDIA_AUTHOR, "");
    meta->SetData(Tag::MEDIA_COMPOSER, "测试");
    int64_t duration = 10030000;
    meta->SetData(Tag::MEDIA_DURATION, duration);
    meta->SetData(Tag::MEDIA_GENRE, "Lyrical");
    bool hasAudio = true;
    meta->SetData(Tag::MEDIA_HAS_AUDIO, hasAudio);
    meta->SetData(Tag::MEDIA_HAS_VIDEO, "yes");
    meta->SetData(Tag::MIME_TYPE, "video/mp4");
    meta->SetData(Tag::MEDIA_TRACK_COUNT, "2");
    int32_t rate = 44100;
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, rate);
    meta->SetData(Tag::MEDIA_TITLE, "test");
    meta->SetData(Tag::VIDEO_HEIGHT, "480");
    meta->SetData(Tag::VIDEO_WIDTH, "720");
    meta->SetData(Tag::MEDIA_DATE, "2022");
    meta->SetData(Tag::VIDEO_ROTATION, Plugins::VideoRotation::VIDEO_ROTATION_0);
 
    Metadata avmeta;
    avmetaDataCollector->ConvertToAVMeta(meta, avmeta);
    EXPECT_FALSE(avmeta.tbl_.size() == 0);
}
 
/**
 * @tc.name: SetStringByValueType
 * @tc.desc: SetStringByValueType
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, SetStringByValueType, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    Metadata avmeta;
    int32_t trackCount = 0;
    meta->SetData(Tag::MEDIA_TRACK_COUNT, trackCount);
    float height = 480;
    meta->SetData(Tag::VIDEO_HEIGHT, height);
 
    bool ret = avmetaDataCollector->SetStringByValueType(meta, avmeta, AV_KEY_NUM_TRACKS, Tag::MEDIA_TRACK_COUNT);
    EXPECT_TRUE(ret);
    ret = avmetaDataCollector->SetStringByValueType(meta, avmeta, AV_KEY_VIDEO_HEIGHT, Tag::VIDEO_HEIGHT);
    EXPECT_TRUE(ret);
    avmetaDataCollector->collectedAVMetaData_ = std::make_shared<Meta>();
    ret = avmetaDataCollector->SetStringByValueType(meta, avmeta, AV_KEY_VIDEO_HEIGHT, Tag::VIDEO_HEIGHT);
    EXPECT_TRUE(ret);
}
 
/**
 * @tc.name: GetVideoTrackInfo_001
 * @tc.desc: GetVideoTrackInfo_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    size_t index = 0;
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    double frameRate = 0;
    bool ret = meta->GetData(Tag::VIDEO_FRAME_RATE, frameRate);
    EXPECT_FALSE(ret);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetVideoTrackInfo_002
 * @tc.desc: GetVideoTrackInfo_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    size_t index = 0;
    double rate = 1;
    meta->SetData(Tag::VIDEO_FRAME_RATE, rate);
    double frameRate = 0;
    bool ret = meta->GetData(Tag::VIDEO_FRAME_RATE, frameRate);
    EXPECT_TRUE(ret);
    EXPECT_EQ(frameRate, rate);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetSarVideoWidth_001
 * @tc.desc: GetSarVideoWidth_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetSarVideoWidth_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    meta->SetData(Tag::VIDEO_WIDTH, 100);
    meta->SetData(Tag::VIDEO_HEIGHT, 100);
    double videoSar = 0;
    bool ret = meta->GetData(Tag::VIDEO_SAR, videoSar);
    EXPECT_FALSE(ret);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta), 100);
}

/**
 * @tc.name: GetSarVideoWidth_002
 * @tc.desc: GetSarVideoWidth_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetSarVideoWidth_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    meta->SetData(Tag::VIDEO_WIDTH, 100);
    meta->SetData(Tag::VIDEO_HEIGHT, 100);
    double sar = 2;
    meta->SetData(Tag::VIDEO_SAR, sar);
    double videoSar = 0;
    bool ret = meta->GetData(Tag::VIDEO_SAR, videoSar);
    EXPECT_TRUE(ret);
    EXPECT_EQ(videoSar, sar);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta), 50);
}

/**
 * @tc.name: GetSarVideoWidth_003
 * @tc.desc: GetSarVideoWidth_003
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetSarVideoWidth_003, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    meta->SetData(Tag::VIDEO_WIDTH, 100);
    meta->SetData(Tag::VIDEO_HEIGHT, 100);
    double sar = 0.5;
    meta->SetData(Tag::VIDEO_SAR, sar);
    double videoSar = 0;
    bool ret = meta->GetData(Tag::VIDEO_SAR, videoSar);
    EXPECT_TRUE(ret);
    EXPECT_EQ(videoSar, sar);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta), 50);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta), 100);
}

/**
 * @tc.name: GetSarVideoWidth_004
 * @tc.desc: GetSarVideoWidth_004
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetSarVideoWidth_004, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    meta->SetData(Tag::VIDEO_WIDTH, 100);
    meta->SetData(Tag::VIDEO_HEIGHT, 100);
    double sar = 1;
    meta->SetData(Tag::VIDEO_SAR, sar);
    double videoSar = 0;
    bool ret = meta->GetData(Tag::VIDEO_SAR, videoSar);
    EXPECT_TRUE(ret);
    EXPECT_EQ(videoSar, sar);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta), 100);
}

/**
 * @tc.name: InitTracksInfoVector_001
 * @tc.desc: InitTracksInfoVector_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "audio/mpeg");
    size_t index = 0;
    std::string mime = "";
    bool ret = meta->GetData(Tag::MIME_TYPE, mime);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->IsAudioMime(mime), true);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_002
 * @tc.desc: InitTracksInfoVector_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "video/avc");
    size_t index = 0;
    std::string mime = "";
    bool ret = meta->GetData(Tag::MIME_TYPE, mime);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->IsVideoMime(mime), true);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_003
 * @tc.desc: InitTracksInfoVector_003
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_003, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "application/x-subrip");
    size_t index = 0;
    std::string mime = "";
    bool ret = meta->GetData(Tag::MIME_TYPE, mime);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->IsSubtitleMime(mime), true);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_004
 * @tc.desc: InitTracksInfoVector_004
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_004, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "text/vtt");
    size_t index = 0;
    std::string mime = "";
    bool ret = meta->GetData(Tag::MIME_TYPE, mime);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->IsSubtitleMime(mime), true);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_005
 * @tc.desc: InitTracksInfoVector_005
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_005, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "invalid");
    size_t index = 0;
    std::string mime = "";
    bool ret = meta->GetData(Tag::MIME_TYPE, mime);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->IsSubtitleMime(mime), false);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_006
 * @tc.desc: InitTracksInfoVector_006
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_006, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_007
 * @tc.desc: InitTracksInfoVector_007
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_007, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::TIMEDMETA);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS