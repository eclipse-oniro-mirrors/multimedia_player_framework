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
    videoMeta->SetData(Tag::VIDEO_ORIENTATION_TYPE, Plugins::VideoOrientationType::ROTATE_NONE);
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
 * @tc.name: GetAVMetadata_001
 * @tc.desc: GetAVMetadata_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata_001, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        { AV_KEY_ALBUM, "media" },
        { AV_KEY_LOCATION_LATITUDE, "test" },
        { AV_KEY_LOCATION_LONGITUDE, "test" },
        { AV_KEY_VIDEO_IS_HDR_VIVID, "yes" },
        { 10086, "test" },
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
 * @tc.name: GetAVMetadata_002
 * @tc.desc: GetAVMetadata_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata_002, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        { AV_KEY_VIDEO_IS_HDR_VIVID, "yes" }
    };
    avmetaDataCollector->collectedAVMetaData_ = nullptr;

    std::shared_ptr<Meta> customerInfo = std::make_shared<Meta>();
    EXPECT_CALL(*mediaDemuxer, GetUserMeta()).WillRepeatedly(Return(nullptr));
    auto meta = avmetaDataCollector->GetAVMetadata();
    EXPECT_TRUE(meta != nullptr);

    int32_t hdr = -1;
    meta->GetData("hdrType", hdr);
    EXPECT_EQ(hdr, static_cast<int32_t>(HdrType::AV_HDR_TYPE_VIVID));
}


/**
 * @tc.name: GetAVMetadata_003
 * @tc.desc: GetAVMetadata_003
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata_003, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        { AV_KEY_VIDEO_IS_HDR_VIVID, "no" }
    };
    avmetaDataCollector->collectedAVMetaData_ = nullptr;

    std::shared_ptr<Meta> customerInfo = std::make_shared<Meta>();
    EXPECT_CALL(*mediaDemuxer, GetUserMeta()).WillRepeatedly(Return(nullptr));
    auto meta = avmetaDataCollector->GetAVMetadata();
    EXPECT_TRUE(meta != nullptr);

    int32_t hdr = -1;
    meta->GetData("hdrType", hdr);
    EXPECT_EQ(hdr, static_cast<int32_t>(HdrType::AV_HDR_TYPE_NONE));
}

/**
 * @tc.name: GetAVMetadata_004
 * @tc.desc: GetAVMetadata_004
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata_004, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        { AV_KEY_LOCATION_LATITUDE, "39.9" },
        { AV_KEY_LOCATION_LONGITUDE, "116.4" }
    };
    avmetaDataCollector->collectedAVMetaData_ = nullptr;
    auto meta = avmetaDataCollector->GetAVMetadata();
    EXPECT_TRUE(meta != nullptr);

    std::string latitude;
    std::string longitude;
    EXPECT_FALSE(meta->GetData("latitude", latitude));
    EXPECT_FALSE(meta->GetData("longitude", longitude));
}

/**
 * @tc.name: GetAVMetadata_005
 * @tc.desc: GetAVMetadata_005
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAVMetadata_005, TestSize.Level1)
{
    avmetaDataCollector->collectedMeta_ = {
        { AV_KEY_VIDEO_DESCRIPTION, "video_description" },
    };
    avmetaDataCollector->collectedAVMetaData_ = nullptr;
    auto meta = avmetaDataCollector->GetAVMetadata();
    EXPECT_TRUE(meta != nullptr);

    std::string description;
    EXPECT_TRUE(meta->GetData("description", description));
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
 * @tc.name: FormatDuration
 * @tc.desc: FormatDuration
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDuration, TestSize.Level1)
{
    Metadata avmeta;
    avmeta.SetMeta(AV_KEY_DURATION, "12000");
    avmetaDataCollector->FormatDuration(avmeta);
    std::string duration = avmeta.GetMeta(AV_KEY_DURATION);
    EXPECT_EQ(duration, "12");

    avmeta.SetMeta(AV_KEY_DURATION, "");
    avmetaDataCollector->FormatDuration(avmeta);
    duration = avmeta.GetMeta(AV_KEY_DURATION);
    EXPECT_EQ(duration, "0");

    avmeta.SetMeta(AV_KEY_DURATION, " ");
    avmetaDataCollector->FormatDuration(avmeta);
    duration = avmeta.GetMeta(AV_KEY_DURATION);
    EXPECT_EQ(duration, "0");

    avmeta.SetMeta(AV_KEY_DURATION, "-12000");
    avmetaDataCollector->FormatDuration(avmeta);
    duration = avmeta.GetMeta(AV_KEY_DURATION);
    EXPECT_EQ(duration, "-12");
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
 * @tc.name: FormatDateTime_001
 * @tc.desc: FormatDateTime_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_001, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "2022";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    EXPECT_TRUE(avmeta.HasMeta(AV_KEY_DATE_TIME));
}

/**
 * @tc.name: FormatDateTime_002
 * @tc.desc: FormatDateTime_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_002, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "20250101";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_EQ(formattedDate, inputDate);
}

/**
 * @tc.name: FormatDateTime_003
 * @tc.desc: FormatDateTime_003
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_003, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "2025-01-01";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_EQ(formattedDate, inputDate);
}

/**
 * @tc.name: FormatDateTime_004
 * @tc.desc: FormatDateTime_004
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_004, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "20250101T120000";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_EQ(formattedDate, inputDate);
}

/**
 * @tc.name: FormatDateTime_005
 * @tc.desc: FormatDateTime_005
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_005, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "just-a-string";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_EQ(formattedDate, inputDate);
}

/**
 * @tc.name: FormatDateTime_006
 * @tc.desc: FormatDateTime_006
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_006, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "2025-01-01T";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_EQ(formattedDate, inputDate);
}

/**
 * @tc.name: FormatDateTime_007
 * @tc.desc: FormatDateTime_007
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatDateTime_007, TestSize.Level1)
{
    Metadata avmeta;
    std::shared_ptr<Meta> globalInfo = make_shared<Meta>();
    std::string inputDate = "2025-01-01T12:00:00Z";
    globalInfo->SetData(Tag::MEDIA_CREATION_TIME, inputDate);
    avmetaDataCollector->FormatDateTime(avmeta, globalInfo);
    std::string formattedDate = avmeta.GetMeta(AV_KEY_DATE_TIME);
    EXPECT_NE(formattedDate, inputDate);
}

/**
 * @tc.name: FormatVideoRotateOrientation
 * @tc.desc: FormatVideoRotateOrientation
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, FormatVideoRotateOrientation, TestSize.Level1)
{
    Metadata avmeta;
    avmeta.SetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION, "");
    avmetaDataCollector->FormatVideoRotateOrientation(avmeta);
    EXPECT_TRUE(avmeta.HasMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION));

    avmeta.SetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION, "a");
    avmetaDataCollector->FormatVideoRotateOrientation(avmeta);
    EXPECT_TRUE(avmeta.HasMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION));

    avmeta.SetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION, "12345");
    avmetaDataCollector->FormatVideoRotateOrientation(avmeta);
    EXPECT_TRUE(avmeta.HasMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION));
}
 
/**
 * @tc.name: ConvertToAVMeta_001
 * @tc.desc: ConvertToAVMeta_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, ConvertToAVMeta_001, TestSize.Level1)
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
 * @tc.name: ConvertToAVMeta_002
 * @tc.desc: ConvertToAVMeta_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, ConvertToAVMeta_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_ALBUM, "album_test");
    meta->SetData(Tag::MEDIA_ALBUM_ARTIST, "album_artist_test");
    meta->SetData(Tag::MEDIA_ARTIST, "artist_test");
    meta->SetData(Tag::MEDIA_AUTHOR, "author_test");
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
    meta->SetData(Tag::VIDEO_COLOR_TRC, Plugins::TransferCharacteristic::HLG);
 
    Metadata avmeta;
    avmetaDataCollector->ConvertToAVMeta(meta, avmeta);
    EXPECT_FALSE(avmeta.tbl_.size() == 0);
}

/**
 * @tc.name: IsAllDigits_001
 * @tc.desc: IsAllDigits_001
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_001, TestSize.Level1)
{
    std::string str = "";
    bool result = avmetaDataCollector->IsAllDigits(str);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsAllDigits_002
 * @tc.desc: IsAllDigits_002
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_002, TestSize.Level1)
{
    std::string str = "1234567890";
    bool result = avmetaDataCollector->IsAllDigits(str);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsAllDigits_003
 * @tc.desc: IsAllDigits_003
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_003, TestSize.Level1)
{
    std::string str = "123abc456";
    bool result = avmetaDataCollector->IsAllDigits(str);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsAllDigits_004
 * @tc.desc: IsAllDigits_004
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_004, TestSize.Level1)
{
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123!456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123@456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123#456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123$456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123.456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123 456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123\t456"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123\n456"));
}

/**
 * @tc.name: IsAllDigits_005
 * @tc.desc: IsAllDigits_005
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_005, TestSize.Level1)
{
    EXPECT_TRUE(avmetaDataCollector->IsAllDigits("0"));
    EXPECT_TRUE(avmetaDataCollector->IsAllDigits("9"));
}

/**
 * @tc.name: IsAllDigits_006
 * @tc.desc: IsAllDigits_006
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_006, TestSize.Level1)
{
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("-123"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("+123"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("-"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("+"));
}

/**
 * @tc.name: IsAllDigits_007
 * @tc.desc: IsAllDigits_007
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, IsAllDigits_007, TestSize.Level1)
{
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits(" 123"));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits("123 "));
    EXPECT_FALSE(avmetaDataCollector->IsAllDigits(" 123 "));
}

/**
 * @tc.name: SetEmptyStringIfNoData
 * @tc.desc: SetEmptyStringIfNoData
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, SetEmptyStringIfNoData, TestSize.Level1)
{
    Metadata avmeta;
    int32_t avKey = 100001;
    EXPECT_FALSE(avmeta.HasMeta(avKey));
    avmetaDataCollector->SetEmptyStringIfNoData(avmeta, avKey);
    EXPECT_TRUE(avmeta.HasMeta(avKey));
    std::string value = avmeta.GetMeta(avKey);
    EXPECT_EQ(value, "");
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
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta, 100), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta, 100), 100);
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
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta, 100), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta, 100), 50);
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
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta, 100), 50);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta, 100), 100);
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
    EXPECT_EQ(avmetaDataCollector->GetSarVideoWidth(meta, 100), 100);
    EXPECT_EQ(avmetaDataCollector->GetSarVideoHeight(meta, 100), 100);
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

/**
 * @tc.name: InitTracksInfoVector_008
 * @tc.desc: InitTracksInfoVector_008
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_008, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::TIMEDMETA);
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, -1);
    meta->SetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, 16);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_009
 * @tc.desc: InitTracksInfoVector_009
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_009, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::TIMEDMETA);
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 16);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_010
 * @tc.desc: InitTracksInfoVector_010
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_010, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 12);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_011
 * @tc.desc: InitTracksInfoVector_011
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_011, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 6);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_012
 * @tc.desc: InitTracksInfoVector_012
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_012, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::ATTACHMENT);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_013
 * @tc.desc: InitTracksInfoVector_013
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_013, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::DATA);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_014
 * @tc.desc: InitTracksInfoVector_014
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_014, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::SUBTITLE);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_015
 * @tc.desc: InitTracksInfoVector_015
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_015, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::VIDEO);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_016
 * @tc.desc: InitTracksInfoVector_016
 * @tc.type: FUNC
 */
 HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_016, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUDIO);
    size_t index = 0;
    Plugins::MediaType mediaType;
    bool ret = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_017
 * @tc.desc: InitTracksInfoVector_017
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_017, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTrackIds = "1,3,5";
    meta->SetData(Tag::REF_TRACK_IDS, refTrackIds);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::REF_TRACK_IDS, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_018
 * @tc.desc: InitTracksInfoVector_018
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_018, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTracktype = "auxl";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_019
 * @tc.desc: InitTracksInfoVector_019
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_019, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "vdep";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_020
 * @tc.desc: InitTracksInfoVector_020
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_020, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTrackIds = "";
    meta->SetData(Tag::REF_TRACK_IDS, refTrackIds);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::REF_TRACK_IDS, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_021
 * @tc.desc: InitTracksInfoVector_021
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_021, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetAudioTrackInfo_001
 * @tc.desc: Test GetAudioTrackInfo with basic audio metadata
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_CHANNEL_COUNT, 2);
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 44100);
    meta->SetData(Tag::MEDIA_BITRATE, 128000LL);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetAudioTrackInfo_002
 * @tc.desc: Test GetAudioTrackInfo with sample depth information
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/wav";
    size_t index = 1;
    
    meta->SetData(Tag::AUDIO_CHANNEL_COUNT, 2);
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 48000);
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 16);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetSubtitleTrackInfo_001
 * @tc.desc: Test GetSubtitleTrackInfo method
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetSubtitleTrackInfo_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "application/x-subrip";
    size_t index = 0;
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetSubtitleTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t trackType = -1;
    trackInfo.GetIntValue("track_type", trackType);
    EXPECT_EQ(trackType, static_cast<int32_t>(Plugins::MediaType::SUBTITLE));
}

/**
 * @tc.name: GetAudioTrackInfo_SampleRate_001
 * @tc.desc: Test GetAudioTrackInfo with common audio sample rate - 44100 Hz
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleRate_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 44100);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t sampleRate = 0;
    trackInfo.GetIntValue("sample_rate", sampleRate);
    EXPECT_EQ(sampleRate, 44100);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleRate_002
 * @tc.desc: Test GetAudioTrackInfo with high resolution audio sample rate - 96000 Hz
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleRate_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/flac";
    size_t index = 1;
    
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 96000);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t sampleRate = 0;
    trackInfo.GetIntValue("sample_rate", sampleRate);
    EXPECT_EQ(sampleRate, 96000);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleRate_003
 * @tc.desc: Test GetAudioTrackInfo with low sample rate - 8000 Hz
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleRate_003, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/amr";
    size_t index = 2;
    
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 8000);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t sampleRate = 0;
    trackInfo.GetIntValue("sample_rate", sampleRate);
    EXPECT_EQ(sampleRate, 8000);
}

/**
 * @tc.name: GetAudioTrackInfo_Bitrate_001
 * @tc.desc: Test GetAudioTrackInfo with common audio bitrate - 128 kbps
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_Bitrate_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 3;
    int64_t bitrateset = 128000;
    meta->SetData(Tag::MEDIA_BITRATE, bitrateset);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t bitrate = 0;
    trackInfo.GetLongValue("bitrate", bitrate);
    
    EXPECT_EQ(bitrate, 128000);
}

/**
 * @tc.name: GetAudioTrackInfo_Bitrate_002
 * @tc.desc: Test GetAudioTrackInfo with high audio bitrate - 320 kbps
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_Bitrate_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 4;
    int64_t bitrateset = 320000;
    meta->SetData(Tag::MEDIA_BITRATE, bitrateset);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t bitrate = 0;
    trackInfo.GetLongValue("bitrate", bitrate);
    EXPECT_EQ(bitrate, 320000);
}

/**
 * @tc.name: GetAudioTrackInfo_Bitrate_003
 * @tc.desc: Test GetAudioTrackInfo with lossless audio bitrate - 1411 kbps
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_Bitrate_003, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/wav";
    size_t index = 5;
    int64_t bitrateset = 1411000;
    meta->SetData(Tag::MEDIA_BITRATE, bitrateset);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t bitrate = 0;
    trackInfo.GetLongValue("bitrate", bitrate);
    EXPECT_EQ(bitrate, 1411000);
}

/**
 * @tc.name: GetAudioTrackInfo_Channels_001
 * @tc.desc: Test GetAudioTrackInfo with stereo audio channels
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_Channels_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 6;
    
    meta->SetData(Tag::AUDIO_CHANNEL_COUNT, 2);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t channels = 0;
    trackInfo.GetIntValue("channel_count", channels);
    EXPECT_EQ(channels, 2);
}

/**
 * @tc.name: GetAudioTrackInfo_Channels_002
 * @tc.desc: Test GetAudioTrackInfo with 5.1 surround audio channels
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_Channels_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/aac";
    size_t index = 7;
    
    meta->SetData(Tag::AUDIO_CHANNEL_COUNT, 6);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t channels = 0;
    trackInfo.GetIntValue("channel_count", channels);
    EXPECT_EQ(channels, 6);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleDepth_001
 * @tc.desc: Test GetAudioTrackInfo with 16-bit audio sample depth
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleDepth_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/wav";
    size_t index = 8;
    
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 16);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t sampleDepth = 0;
    trackInfo.GetLongValue("sample_depth", sampleDepth);
    EXPECT_EQ(sampleDepth, 16);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleDepth_002
 * @tc.desc: Test GetAudioTrackInfo with 24-bit audio sample depth
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleDepth_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/flac";
    size_t index = 9;
    
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 24);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t sampleDepth = 0;
    trackInfo.GetLongValue("sample_depth", sampleDepth);
    EXPECT_EQ(sampleDepth, 24);
}

/**
 * @tc.name: GetOtherTrackInfo_001
 * @tc.desc: Test GetOtherTrackInfo with auxiliary track
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetOtherTrackInfo_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    size_t index = 0;
    
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetOtherTrackInfo(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetOtherTrackInfo_002
 * @tc.desc: Test GetOtherTrackInfo with timed metadata track
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetOtherTrackInfo_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    size_t index = 1;
    
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::TIMEDMETA);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetOtherTrackInfo(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleRateAndBitrate_001
 * @tc.desc: Test GetAudioTrackInfo with both sample rate and bitrate set to zero
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleRateAndBitrate_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/mpeg";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, 0);
    meta->SetData(Tag::MEDIA_BITRATE, 0LL);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t sampleRate = -1;
    int64_t bitrate = -1;
    trackInfo.GetIntValue("sample_rate", sampleRate);
    trackInfo.GetLongValue("bitrate", bitrate);
    EXPECT_EQ(sampleRate, 0);
    EXPECT_EQ(bitrate, 0);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleDepthPriority_001
 * @tc.desc: Test GetAudioTrackInfo prioritizes AUDIO_BITS_PER_CODED_SAMPLE over AUDIO_BITS_PER_RAW_SAMPLE
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleDepthPriority_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/flac";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 24);
    meta->SetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, 16);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t sampleDepth = 0;
    trackInfo.GetLongValue("sample_depth", sampleDepth);
    EXPECT_EQ(sampleDepth, 24);
}

/**
 * @tc.name: GetAudioTrackInfo_SampleDepthFallback_001
 * @tc.desc: Test GetAudioTrackInfo falls back to AUDIO_BITS_PER_RAW_SAMPLE when AUDIO_BITS_PER_CODED_SAMPLE is invalid
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_SampleDepthFallback_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/wav";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 0); // Invalid value
    meta->SetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, 32);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t sampleDepth = 0;
    trackInfo.GetLongValue("sample_depth", sampleDepth);
    EXPECT_EQ(sampleDepth, 32);
}

/**
 * @tc.name: GetAudioTrackInfo_NoSampleDepth_001
 * @tc.desc: Test GetAudioTrackInfo when no valid sample depth is available
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_NoSampleDepth_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/aac";
    size_t index = 0;
    
    meta->SetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, 0);
    meta->SetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, 0);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int64_t sampleDepth = -1;
    bool hasSampleDepth = trackInfo.GetLongValue("sample_depth", sampleDepth);
    EXPECT_FALSE(hasSampleDepth); // sample_depth should not be set
}

/**
 * @tc.name: GetAudioTrackInfo_TrackInfoValues_001
 * @tc.desc: Test GetAudioTrackInfo sets correct track index, type and mime
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetAudioTrackInfo_TrackInfoValues_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "audio/aac";
    size_t index = 5;
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetAudioTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t trackIndex = -1;
    int32_t trackType = -1;
    std::string codecMime;
    
    trackInfo.GetIntValue("track_index", trackIndex);
    trackInfo.GetIntValue("track_type", trackType);
    trackInfo.GetStringValue("codec_mime", codecMime);
    
    EXPECT_EQ(trackIndex, 5);
    EXPECT_EQ(trackType, static_cast<int32_t>(Plugins::MediaType::AUDIO));
    EXPECT_EQ(codecMime, "audio/aac");
}

/**
 * @tc.name: GetVideoTrackInfo_FrameRate_001
 * @tc.desc: Test GetVideoTrackInfo with fractional frame rate
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_FrameRate_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/mp4";
    size_t index = 0;
    
    meta->SetData(Tag::VIDEO_FRAME_RATE, 29.97);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    double frameRate = 0.0;
    trackInfo.GetDoubleValue("frame_rate", frameRate);
    EXPECT_DOUBLE_EQ(frameRate, 2997.0); // 29.97 * 100 (FRAME_RATE_UNIT_MULTIPLE)
}

/**
 * @tc.name: GetVideoTrackInfo_HDR_001
 * @tc.desc: Test GetVideoTrackInfo with HDR vivid set to true
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_HDR_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/mp4";
    size_t index = 0;
    
    meta->SetData(Tag::VIDEO_IS_HDR_VIVID, true);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t hdrType = -1;
    trackInfo.GetIntValue("hdr_type", hdrType);
    EXPECT_EQ(hdrType, 1); // true is converted to 1
}

/**
 * @tc.name: GetVideoTrackInfo_HDR_002
 * @tc.desc: Test GetVideoTrackInfo with HDR vivid set to false
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_HDR_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/mp4";
    size_t index = 0;
    
    meta->SetData(Tag::VIDEO_IS_HDR_VIVID, false);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t hdrType = -1;
    trackInfo.GetIntValue("hdr_type", hdrType);
    EXPECT_EQ(hdrType, 0); // false is converted to 0
}

/**
 * @tc.name: GetVideoTrackInfo_Dimensions_001
 * @tc.desc: Test GetVideoTrackInfo with specific width and height values
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, GetVideoTrackInfo_Dimensions_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string mime = "video/avc";
    size_t index = 0;
    
    meta->SetData(Tag::VIDEO_WIDTH, 1920);
    meta->SetData(Tag::VIDEO_HEIGHT, 1080);
    
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->GetVideoTrackInfo(meta, mime, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
    
    auto& trackInfo = avmetaDataCollector->trackInfoVec_.back();
    int32_t width = -1;
    int32_t height = -1;
    int32_t originalWidth = -1;
    int32_t originalHeight = -1;
    
    trackInfo.GetIntValue("width", width);
    trackInfo.GetIntValue("height", height);
    trackInfo.GetIntValue("original_width", originalWidth);
    trackInfo.GetIntValue("original_height", originalHeight);
    
    EXPECT_EQ(originalWidth, 1920);
    EXPECT_EQ(originalHeight, 1080);
    EXPECT_EQ(width, 1920);
    EXPECT_EQ(height, 1080);
}

/**
 * @tc.name: VectorToString_001
 * @tc.desc: Test VectorToString with specific values
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, VectorToString_001, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);
    std::vector<int> vectest = {1, 3, 5};
    std::string strtest;
    strtest = avmetaDataCollector->VectorToString(vectest);
    EXPECT_EQ(strtest, "1,3,5");
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: VectorToString_002
 * @tc.desc: Test VectorToString with specific values
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, VectorToString_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);
    std::vector<int> vectest = {2};
    std::string strtest;
    strtest = avmetaDataCollector->VectorToString(vectest);
    EXPECT_EQ(strtest, "2");
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: VectorToString_003
 * @tc.desc: Test VectorToString with specific values
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, VectorToString_003, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);
    std::vector<int> vectest;
    std::string strtest;
    strtest = avmetaDataCollector->VectorToString(vectest);
    EXPECT_EQ(strtest, "");
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_022
 * @tc.desc: InitTracksInfoVector_022
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_022, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::MEDIA_TYPE, Plugins::MediaType::AUXILIARY);
    std::string refTracktype = "cdsc";
    meta->SetData(Tag::TRACK_REF_TYPE, refTracktype);

    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_023
 * @tc.desc: InitTracksInfoVector_023
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_023, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTrackIds = "23,34";
    meta->SetData(Tag::REF_TRACK_IDS, refTrackIds);
    std::string refTrackType = "vdep";
    meta->SetData(Tag::TRACK_REF_TYPE, refTrackType);
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::REF_TRACK_IDS, result);
    EXPECT_TRUE(ret);
    ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_024
 * @tc.desc: InitTracksInfoVector_024
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_024, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTrackIds = "";
    meta->SetData(Tag::REF_TRACK_IDS, refTrackIds);
    std::string refTrackType = "vdep";
    meta->SetData(Tag::TRACK_REF_TYPE, refTrackType);
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::REF_TRACK_IDS, result);
    EXPECT_TRUE(ret);
    ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}

/**
 * @tc.name: InitTracksInfoVector_025
 * @tc.desc: InitTracksInfoVector_025
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataCollectorUnitTest, InitTracksInfoVector_025, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::string refTrackIds = "2";
    meta->SetData(Tag::REF_TRACK_IDS, refTrackIds);
    std::string refTrackType = "auxl";
    meta->SetData(Tag::TRACK_REF_TYPE, refTrackType);
    size_t index = 0;
    std::string result;
    bool ret = meta->GetData(Tag::REF_TRACK_IDS, result);
    EXPECT_TRUE(ret);
    ret = meta->GetData(Tag::TRACK_REF_TYPE, result);
    EXPECT_TRUE(ret);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 0);
    avmetaDataCollector->InitTracksInfoVector(meta, index);
    EXPECT_EQ(avmetaDataCollector->trackInfoVec_.size(), 1);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS