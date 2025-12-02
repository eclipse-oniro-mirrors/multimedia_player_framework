/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "media_errors.h"
#include "avmetadata_unit_test.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace AVMetadataTestParam;

namespace OHOS {
namespace Media {
/**
    Function: compare metadata
    Description: test for metadata
    Input: uri, expected MetaData
    Return: null
*/
void AVMetadataUnitTest::CheckMeta(std::string uri, std::unordered_map<int32_t, std::string> expectMeta)
{
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_META_ONLY));
    for (auto &item : expectMeta) {
        std::string value = helper->ResolveMetadata(item.first);
        EXPECT_EQ(AVMetadataTestBase::GetInstance().CompareMetadata(item.first, value, item.second), true);
    }
    auto resultMetas = helper->ResolveMetadata();
    EXPECT_EQ(AVMetadataTestBase::GetInstance().CompareMetadata(resultMetas, expectMeta), true);
    helper->Release();
}

/**
    * @tc.number    : GetThumbnail
    * @tc.name      : Get Thumbnail
    * @tc.desc      : Get THUMBNAIL Function case
*/
void AVMetadataUnitTest::GetThumbnail(const std::string uri)
{
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    struct PixelMapParams param = {-1, -1, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    ASSERT_NE(nullptr, frame);
    helper->FrameToFile(frame, testInfo_->name(), timeUs, queryOption);
    helper->FrameToJpeg(frame, testInfo_->name(), timeUs, queryOption);
    timeUs = 5000000;  // 5000000us
    queryOption = AVMetadataQueryOption::AV_META_QUERY_PREVIOUS_SYNC;
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    ASSERT_NE(nullptr, frame);
    helper->FrameToFile(frame, testInfo_->name(), timeUs, queryOption);
    helper->FrameToJpeg(frame, testInfo_->name(), timeUs, queryOption);

    param = {-1, -1, PixelFormat::RGB_888};
    queryOption = AVMetadataQueryOption::AV_META_QUERY_CLOSEST_SYNC;
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    ASSERT_NE(nullptr, frame);
    helper->FrameToFile(frame, testInfo_->name(), timeUs, queryOption);
    helper->FrameToJpeg(frame, testInfo_->name(), timeUs, queryOption);

    timeUs = 0;
    queryOption = AVMetadataQueryOption::AV_META_QUERY_CLOSEST;
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    ASSERT_NE(nullptr, frame);
    helper->FrameToFile(frame, testInfo_->name(), timeUs, queryOption);
    helper->FrameToJpeg(frame, testInfo_->name(), timeUs, queryOption);
    helper->Release();
}

/**
 * @tc.number    : ResolveMetadata_Format_MP4_0100
 * @tc.name      : 01.MP4 format Get MetaData(H264+AAC)
 * @tc.desc      : test ResolveMetadata
 */
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0100, TestSize.Level0)
{
    EXPECT_META[AV_KEY_DATE_TIME] = "2022-05-30 06:10:43";
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    CheckMeta(uri, EXPECT_META);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP4_0200
    * @tc.name      : 02.MP4 format Get MetaData(H264+MP3)
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0200, Function | MediumTest | Level0)
{
    EXPECT_META[AV_KEY_DATE_TIME] = "2022";
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/H264_MP3.mp4");
    CheckMeta(uri, EXPECT_META);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP4_0500
    * @tc.name      : 05.MP4 format Get MetaData(MPEG4+AAC)
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0500, Function | MediumTest | Level0)
{
    EXPECT_META[AV_KEY_DATE_TIME] = "2022-05-29 22:46:43";
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/MPEG4_AAC.mp4");
    CheckMeta(uri, EXPECT_META);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP4_0600
    * @tc.name      : 06.MP4 format Get MetaData(MPEG4+MP3)
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0600, Function | MediumTest | Level0)
{
    EXPECT_META[AV_KEY_DATE_TIME] = "2022-05";
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/MPEG4_MP3.mp4");
    CheckMeta(uri, EXPECT_META);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP4_0700
    * @tc.name      : 07.MP4 format Get MetaData(HDR)
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0700, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta;
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/HDR.mp4");
    #ifndef CHECKING_VIDEO_IS_HDR_VIVID
    expectMeta.insert(std::make_pair(AV_KEY_VIDEO_IS_HDR_VIVID, ""));
    #else
    expectMeta.insert(std::make_pair(AV_KEY_VIDEO_IS_HDR_VIVID, "yes"));
    #endif
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP4_0800
    * @tc.name      : 08.MP4 format Get MetaData(SDR)
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP4_0800, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta;
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/SDR.mp4");
    expectMeta.insert(std::make_pair(AV_KEY_VIDEO_IS_HDR_VIVID, ""));
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_M4A_0100
    * @tc.name      : 01.M4A format Get MetaData
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_M4A_0100, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_ALBUM_ARTIST, "media_test"},
        {AV_KEY_ARTIST, "元数据测试"},
        {AV_KEY_AUTHOR, ""},
        {AV_KEY_COMPOSER, "测试"},
        {AV_KEY_DURATION, "219562"},
        {AV_KEY_GENRE, "Lyrical"},
        {AV_KEY_HAS_AUDIO, "yes"},
        {AV_KEY_HAS_VIDEO, ""},
        {AV_KEY_MIME_TYPE, "audio/mp4"},
        {AV_KEY_NUM_TRACKS, "1"},
        {AV_KEY_SAMPLE_RATE, "48000"},
        {AV_KEY_TITLE, "test"},
        {AV_KEY_VIDEO_HEIGHT, ""},
        {AV_KEY_VIDEO_WIDTH, ""},
        {AV_KEY_DATE_TIME, "2015-11-23"},
    };
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/aac_48000Hz_70kbs_mono.m4a");
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_MP3_0100
    * @tc.name      : 01.MP3 format Get MetaData
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_MP3_0100, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_ALBUM_ARTIST, "media_test"},
        {AV_KEY_ARTIST, "元数据测试"},
        {AV_KEY_AUTHOR, "media"},
        {AV_KEY_COMPOSER, "测试"},
        {AV_KEY_DURATION, "219600"},
        {AV_KEY_GENRE, "Lyrical"},
        {AV_KEY_HAS_AUDIO, "yes"},
        {AV_KEY_HAS_VIDEO, ""},
        {AV_KEY_MIME_TYPE, "audio/mpeg"},
        {AV_KEY_NUM_TRACKS, "1"},
        {AV_KEY_SAMPLE_RATE, "48000"},
        {AV_KEY_TITLE, "test"},
        {AV_KEY_VIDEO_HEIGHT, ""},
        {AV_KEY_VIDEO_WIDTH, ""},
        {AV_KEY_DATE_TIME, "2022-05"},
    };
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/mp3_48000Hz_64kbs_mono.mp3");
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_AAC_0100
    * @tc.name      : 01.AAC format Get MetaData
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_AAC_0100, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta = {
        {AV_KEY_ALBUM, ""},
        {AV_KEY_ALBUM_ARTIST, ""},
        {AV_KEY_ARTIST, ""},
        {AV_KEY_AUTHOR, ""},
        {AV_KEY_COMPOSER, ""},
        {AV_KEY_DURATION, "219780"},
        {AV_KEY_GENRE, ""},
        {AV_KEY_HAS_AUDIO, "yes"},
        {AV_KEY_HAS_VIDEO, ""},
        {AV_KEY_MIME_TYPE, "audio/aac-adts"},
        {AV_KEY_NUM_TRACKS, "1"},
        {AV_KEY_SAMPLE_RATE, "44100"},
        {AV_KEY_TITLE, ""},
        {AV_KEY_VIDEO_HEIGHT, ""},
        {AV_KEY_VIDEO_WIDTH, ""},
    };
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/aac_44100Hz_143kbs_stereo.aac");
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_WAV_0100
    * @tc.name      : 01.WAV format Get MetaData
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_WAV_0100, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_ARTIST, "元数据测试"},
        {AV_KEY_ALBUM_ARTIST, ""},
        {AV_KEY_COMPOSER, ""},
        {AV_KEY_AUTHOR, ""},
        {AV_KEY_GENRE, "Lyrical"},
        {AV_KEY_DURATION, "5460"},
        {AV_KEY_HAS_VIDEO, ""},
        {AV_KEY_HAS_AUDIO, "yes"},
        {AV_KEY_MIME_TYPE, "audio/wav"},
        {AV_KEY_SAMPLE_RATE, "48000"},
        {AV_KEY_NUM_TRACKS, "1"},
        {AV_KEY_DATE_TIME, "2022-05-29 22:46:43"},
        {AV_KEY_TITLE, "test"},
        {AV_KEY_VIDEO_WIDTH, ""},
        {AV_KEY_VIDEO_HEIGHT, ""},
    };
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/pcm_s16le_48000Hz_768kbs_mono.wav");
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : ResolveMetadata_Format_WAV_0200
    * @tc.name      : 01.WAV format Get MetaData
    * @tc.desc      : test ResolveMetadata
*/
HWTEST_F(AVMetadataUnitTest, ResolveMetadata_Format_WAV_0200, Function | MediumTest | Level0)
{
    std::unordered_map<int32_t, std::string> expectMeta = {
        {AV_KEY_ALBUM, "media"},
        {AV_KEY_ALBUM_ARTIST, ""},
        {AV_KEY_ARTIST, "元数据测试"},
        {AV_KEY_AUTHOR, ""},
        {AV_KEY_COMPOSER, ""},
        {AV_KEY_DURATION, "5460"},
        {AV_KEY_GENRE, "Lyrical"},
        {AV_KEY_HAS_AUDIO, "yes"},
        {AV_KEY_HAS_VIDEO, ""},
        {AV_KEY_MIME_TYPE, "audio/wav"},
        {AV_KEY_NUM_TRACKS, "1"},
        {AV_KEY_SAMPLE_RATE, "48000"},
        {AV_KEY_TITLE, "test"},
        {AV_KEY_VIDEO_HEIGHT, ""},
        {AV_KEY_VIDEO_WIDTH, ""},
        {AV_KEY_DATE_TIME, "2022"},
    };
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("/pcm_s16le_48000Hz_768kbs_mono_date.wav");
    CheckMeta(uri, expectMeta);
}

/**
    * @tc.number    : FetchArtPicture_Format_MP3_0100
    * @tc.name      : Get SURFACE FROM MP3_SURFACE.mp3
    * @tc.desc      : Get SURFACE FROM MP3_SURFACE.mp3
*/
HWTEST_F(AVMetadataUnitTest, FetchArtPicture_Format_MP3_0100, Function | MediumTest | Level0)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("MP3_SURFACE.mp3");

    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    std::shared_ptr<AVSharedMemory> frame = helper->FetchArtPicture();
    helper->SurfaceToFile(frame, testInfo_->name());
    ASSERT_EQ(51.3046875*1024, frame->GetSize());
}

/**
    * @tc.number    : FetchArtPicture_Format_MP3_0200
    * @tc.name      : Get ArtPicture FROM H264_AAC.mp4
    * @tc.desc      : Get ArtPicture FROM H264_AAC.mp4
*/
HWTEST_F(AVMetadataUnitTest, FetchArtPicture_Format_MP3_0200, Function | MediumTest | Level0)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");

    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    std::shared_ptr<AVSharedMemory> frame = helper->FetchArtPicture();
    ASSERT_EQ(nullptr, frame);
}

/**
 * @tc.number    : FetchFrameAtTime_Resolution_0100
 * @tc.name      : Resolution 170x170
 * @tc.desc      : Get THUMBNAIL
 */
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_Resolution_0100, TestSize.Level0)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("out_170_170.mp4");
    GetThumbnail(uri);
}

/**
 * @tc.number    : FetchFrameAtTime_Resolution_0200
 * @tc.name      : Resolution 480x320
 * @tc.desc      : Get THUMBNAIL
 */
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_Resolution_0200, TestSize.Level0)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("out_480_320.mp4");
    GetThumbnail(uri);
}

/**
    * @tc.number    : FetchFrameAtTime_API_0100
    * @tc.name      : FetchFrameAtTime size
    * @tc.desc      : FetchFrameAtTime API size
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_API_0100, TestSize.Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    struct PixelMapParams param = {-1, 316, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {dstWidthMin - 1, 316, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {dstWidthMin, 316, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {dstWidthMax, 316, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {dstWidthMax + 1, 316, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, -1, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, 0, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, dstHeightMin - 1, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, dstHeightMin, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, dstHeightMax, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    param = {316, dstHeightMax + 1, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    timeUs = -1;
    param = {316, 316, PixelFormat::RGB_565};
    frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : FetchFrameAtTime_API_0200
    * @tc.name      : FetchFrameAtTime AVMetadataQueryOption
    * @tc.desc      : FetchFrameAtTime API AVMetadataQueryOption
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_API_0200, TestSize.Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    struct PixelMapParams param = {-1, 316, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption(100);
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : FetchFrameAtTime_API_0300
    * @tc.name      : FetchFrameAtTime PixelFormat
    * @tc.desc      : FetchFrameAtTime API PixelFormat
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_API_0300, TestSize.Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    struct PixelMapParams param = {-1, 316, PixelFormat::UNKNOWN};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : FetchFrameAtTime_API_0400
    * @tc.name      : FetchFrameAtTime PixelFormat
    * @tc.desc      : FetchFrameAtTime API PixelFormat RGBA_8888
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_API_0400, TestSize.Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    struct PixelMapParams param = {-1, 316, PixelFormat::RGBA_8888};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : FetchFrameAtTime
    * @tc.name      : FetchFrameAtTime AV_META_USAGE_META_ONLY
    * @tc.desc      : FetchFrameAtTime API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameAtTime_API_0500, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_META_ONLY));

    std::string value = helper->ResolveMetadata(AV_KEY_HAS_VIDEO);
    EXPECT_NE(value, " ");
    helper->ResolveMetadata();
    struct PixelMapParams param = {-1, 316, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_NE(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : SetSource_API_0100
    * @tc.name      : SetSource AVMetadataUsage
    * @tc.desc      : SetSource API AVMetadataUsage
*/
HWTEST_F(AVMetadataUnitTest, SetSource_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    EXPECT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage(100)));
    helper->Release();
}

/**
    * @tc.number    : SetSource_API_0200
    * @tc.name      : SetSource
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, SetSource_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    struct PixelMapParams param = {-1, 316, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    std::string value = helper->ResolveMetadata(AV_KEY_HAS_VIDEO);
    EXPECT_NE(value, " ");
    helper->ResolveMetadata();
    helper->Release();
}

/**
    * @tc.number    : SetSource_API_0400
    * @tc.name      : SetSource 1kb.mp3
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, SetSource_API_0400, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("aac_44100Hz_143kbs_stereo.aac");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));

    std::string value = helper->ResolveMetadata(AV_KEY_HAS_VIDEO);
    EXPECT_EQ(value, "");
    helper->ResolveMetadata(AV_KEY_HAS_AUDIO);
    EXPECT_EQ(value, "");
    helper->ResolveMetadata();
    struct PixelMapParams param = {-1, 316, PixelFormat::RGB_565};
    int64_t timeUs = 0;
    int32_t queryOption = AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC;
    std::shared_ptr<PixelMap> frame = helper->FetchFrameAtTime(timeUs, queryOption, param);
    EXPECT_EQ(nullptr, frame);
    helper->Release();
}

/**
    * @tc.number    : SetSource_API_0500
    * @tc.name      : SetSource error.mp4
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, SetSource_API_0500, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("error.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    uint64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(0, time, param);
    ASSERT_EQ(pixelMap, nullptr);
}

/**
    * @tc.number    : SetSource_API_0600
    * @tc.name      : SetSource invalid.mp4
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, SetSource_API_0600, Level2)
{
    std::string uri = "file:///data/test/invalid.mp4";
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_NE(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
}

/**
    * @tc.number    : GetFrameIndexByTime_API_0100
    * @tc.name      : SetSource H264_AAC.mp4
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, GetFrameIndexByTime_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    uint32_t index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetFrameIndexByTime(0, index));
}

/**
    * @tc.number    : GetTimeByFrameIndex_API_0100
    * @tc.name      : SetSource H264_AAC.mp4
    * @tc.desc      : SetSource API
*/
HWTEST_F(AVMetadataUnitTest, GetTimeByFrameIndex_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    uint64_t time = 0;
    ASSERT_EQ(MSERR_OK, helper->GetTimeByFrameIndex(0, time));
}

/**
    * @tc.number    : GetFrameIndexByTime_PtsAndFrame_API_0100
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : get pts by frameIndex(video track)
*/
HWTEST_F(AVMetadataUnitTest, GetFrameIndexByTime_PtsAndFrame_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 66666;
    uint32_t index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetFrameIndexByTime(time, index));
    ASSERT_EQ(index, 4);
}

/**
    * @tc.number    : GetFrameIndexByTime_PtsAndFrame_API_0200
    * @tc.name      : SetSource h264.flv
    * @tc.desc      : get pts by frameIndex(not mp4)
*/
HWTEST_F(AVMetadataUnitTest, GetFrameIndexByTime_PtsAndFrame_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("h264.flv");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 69659;
    uint32_t index = 0;
    ASSERT_NE(MSERR_OK, helper->GetFrameIndexByTime(time, index));
}

/**
    * @tc.number    : GetTimeByFrameIndex_PtsAndFrame_API_0100
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : get pts by frameIndex(video track)
*/
HWTEST_F(AVMetadataUnitTest, GetTimeByFrameIndex_PtsAndFrame_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 2;
    ASSERT_EQ(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
    ASSERT_EQ(time, 33333);
}

/**
    * @tc.number    : GetTimeByFrameIndex_PtsAndFrame_API_0200
    * @tc.name      : SetSource h264.flv
    * @tc.desc      : get pts by frameIndex(not mp4)
*/
HWTEST_F(AVMetadataUnitTest, GetTimeByFrameIndex_PtsAndFrame_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("h264.flv");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 10;
    ASSERT_NE(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
}

/**
    * @tc.number    : PtsAndFrameIndexConversion_API_0100
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : pts and frameIndex convertion test(pts -> frameIndex -> pts)
*/
HWTEST_F(AVMetadataUnitTest, PtsAndFrameIndexConversion_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 66666;
    uint32_t index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetFrameIndexByTime(time, index));
    ASSERT_EQ(index, 4);
    time = 0;
    ASSERT_EQ(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
    ASSERT_EQ(time, 66666);
}

/**
    * @tc.number    : PtsAndFrameIndexConversion_API_0200
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : pts and frameIndex convertion test(frameIndex -> pts -> frameIndex)
*/
HWTEST_F(AVMetadataUnitTest, PtsAndFrameIndexConversion_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 4;
    ASSERT_EQ(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
    ASSERT_EQ(time, 66666);
    index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetFrameIndexByTime(time, index));
    ASSERT_EQ(index, 4);
}

/**
    * @tc.number    : PTSOutOfRange_0100
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : pts out of range
*/
HWTEST_F(AVMetadataUnitTest, PTSOutOfRange_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 999999999;
    uint32_t index = 0;
    ASSERT_NE(MSERR_OK, helper->GetFrameIndexByTime(time, index));
}

/**
    * @tc.number    : IndexOutOfRange_API_0100
    * @tc.name      : SetSource camera_info_parser.mp4
    * @tc.desc      : Index out of range
*/
HWTEST_F(AVMetadataUnitTest, IndexOutOfRange_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("camera_info_parser.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 9999999;
    ASSERT_NE(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
}

/**
    * @tc.number    : SetSourceDoubleVideoTrack_API_0100
    * @tc.name      : SetSource h264_double_video_audio.mp4
    * @tc.desc      : double video track index
*/
HWTEST_F(AVMetadataUnitTest, SetSourceDoubleVideoTrack_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("h264_double_video_audio.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetFrameIndexByTime(time, index));
}

/**
    * @tc.number    : SetSourceDoubleVideoTrack_API_0200
    * @tc.name      : SetSource h264_double_video_audio.mp4
    * @tc.desc      : double video track index
*/
HWTEST_F(AVMetadataUnitTest, SetSourceDoubleVideoTrack_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
                      std::string("h264_double_video_audio.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT));
    uint64_t time = 0;
    uint32_t index = 0;
    ASSERT_EQ(MSERR_OK, helper->GetTimeByFrameIndex(index, time));
}

/**
    * @tc.number    : FetchFrameYuv_API_0100
    * @tc.name      : FetchFrameYuv SDR.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0200
    * @tc.name      : FetchFrameYuv HDR.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("HDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1080);
    ASSERT_EQ(pixelMap->GetHeight(), 2336);
}

/**
    * @tc.number    : FetchFrameYuv_API_0300
    * @tc.name      : FetchFrameYuv SDR.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0300, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.isSupportFlip = true;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0400
    * @tc.name      : FetchFrameYuv SDR_HF.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0400, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR_HF.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0500
    * @tc.name      : FetchFrameYuv SDR_HF.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0500, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR_HF.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.isSupportFlip = true;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0600
    * @tc.name      : FetchFrameYuv request.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0600, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("request.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.convertColorSpace = false;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0700
    * @tc.name      : FetchFrameYuv mbaff.mp4
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0700, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("mbaff.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.convertColorSpace = false;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
}

/**
    * @tc.number    : FetchFrameYuv_API_0800
    * @tc.name      : FetchFrameYuv H264_AAC.mp4 abnormal
    * @tc.desc      : FetchFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchFrameYuv_API_0800, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 360;
    param.dstHeight = 240;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 360);
    ASSERT_EQ(pixelMap->GetHeight(), 240);

    param.dstWidth = 500;
    param.dstHeight = 1000;
    pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);
}

/**
    * @tc.number    : FetchScaledFrameYuv_API_0100
    * @tc.name      : FetchScaledFrameYuv H264_AAC.mp4 custom scaling
    * @tc.desc      : FetchScaledFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchScaledFrameYuv_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 300;
    param.dstHeight = 200;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 300);
    ASSERT_EQ(pixelMap->GetHeight(), 200);
}

/**
    * @tc.number    : FetchScaledFrameYuv_API_0200
    * @tc.name      : FetchScaledFrameYuv H264_AAC.mp4 side scaling
    * @tc.desc      : FetchScaledFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchScaledFrameYuv_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 300;
    param.dstHeight = -1;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 300);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = -1;
    param.dstHeight = 200;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 200);
}

/**
    * @tc.number    : FetchScaledFrameYuv_API_0300
    * @tc.name      : FetchScaledFrameYuv H264_AAC.mp4 no scaling
    * @tc.desc      : FetchScaledFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchScaledFrameYuv_API_0300, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = -1;
    param.dstHeight = -1;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = 0;
    param.dstHeight = 0;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);
}

/**
    * @tc.number    : FetchScaledFrameYuv_API_0400
    * @tc.name      : FetchScaledFrameYuv H264_AAC.mp4 proportional scaling
    * @tc.desc      : FetchScaledFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchScaledFrameYuv_API_0400, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 360;
    param.dstHeight = 0;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 360);
    ASSERT_EQ(pixelMap->GetHeight(), 240);

    param.dstWidth = 0;
    param.dstHeight = 240;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 360);
    ASSERT_EQ(pixelMap->GetHeight(), 240);
}

/**
    * @tc.number    : FetchScaledFrameYuv_API_0500
    * @tc.name      : FetchScaledFrameYuv H264_AAC.mp4 abnormal
    * @tc.desc      : FetchScaledFrameYuv API
*/
HWTEST_F(AVMetadataUnitTest, FetchScaledFrameYuv_API_0500, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 1000;
    param.dstHeight = 200;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = 500;
    param.dstHeight = 1000;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);
}

/**
    * @tc.number    : SetUrlSource_API_0100
    * @tc.name      : SetUrlSource test url
    * @tc.desc      : SetUrlSource API
*/
HWTEST_F(AVMetadataUnitTest, SetUrlSource_API_0100, Level2)
{
    std::string uri = "";
    std::map<std::string, std::string> header;
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_NE(MSERR_OK, helper->SetUrlSource(uri, header));
    uri = AVMetadataTestBase::GetInstance().GetMountPath() + std::string("HDR.mp4");
    ASSERT_NE(MSERR_OK, helper->SetUrlSource(uri, header));
    uri = "http://XXX";
    ASSERT_EQ(MSERR_OK, helper->SetUrlSource(uri, header));
    helper->Release();
}

/**
    * @tc.number    : SetUrlSource_API_0200
    * @tc.name      : SetUrlSource test url
    * @tc.desc      : SetUrlSource API
*/
HWTEST_F(AVMetadataUnitTest, SetUrlSource_API_0200, Level2)
{
    std::string uri = "";
    std::map<std::string, std::string> header;
    header.emplace("User-Agent", "User-Agent-Value");
    header.emplace("Date", "2025 08:20:45");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_NE(MSERR_OK, helper->SetUrlSource(uri, header));
    uri = AVMetadataTestBase::GetInstance().GetMountPath() + std::string("HDR.mp4");
    ASSERT_NE(MSERR_OK, helper->SetUrlSource(uri, header));
    uri = "https://XXX";
    ASSERT_EQ(MSERR_OK, helper->SetUrlSource(uri, header));
    helper->Release();
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0100
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0100, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
    helper->Release();
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0200
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0200, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_IMAGE_GENERATOR));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
    helper->Release();
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0300
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0300, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("SDR.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_META_DATA_DEFAULT));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 1920);
    ASSERT_EQ(pixelMap->GetHeight(), 1080);
    helper->Release();
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0400
    * @tc.name      : SetAVMetadataCaller H264_AAC.mp4 custom scaling
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0400, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 300;
    param.dstHeight = 200;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 300);
    ASSERT_EQ(pixelMap->GetHeight(), 200);
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0500
    * @tc.name      : SetAVMetadataCaller H264_AAC.mp4 side scaling
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0500, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 300;
    param.dstHeight = -1;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 300);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = -1;
    param.dstHeight = 200;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 200);
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0600
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0600, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = -1;
    param.dstHeight = -1;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = 0;
    param.dstHeight = 0;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0700
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0700, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 360;
    param.dstHeight = 0;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 360);
    ASSERT_EQ(pixelMap->GetHeight(), 240);

    param.dstWidth = 0;
    param.dstHeight = 240;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 360);
    ASSERT_EQ(pixelMap->GetHeight(), 240);
}

/**
    * @tc.number    : SetAVMetadataCaller_API_0800
    * @tc.name      : SetAVMetadataCaller test url
    * @tc.desc      : SetAVMetadataCaller API
*/
HWTEST_F(AVMetadataUnitTest, SetAVMetadataCaller_API_0800, Level2)
{
    std::string uri = AVMetadataTestBase::GetInstance().GetMountPath() +
        std::string("H264_AAC.mp4");
    std::shared_ptr<AVMetadataMock> helper = std::make_shared<AVMetadataMock>();
    ASSERT_NE(nullptr, helper);
    ASSERT_EQ(true, helper->CreateAVMetadataHelper());
    ASSERT_EQ(MSERR_OK, helper->SetSource(uri, 0, 0, AVMetadataUsage::AV_META_USAGE_PIXEL_MAP));
    ASSERT_EQ(MSERR_OK, helper->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR));
    int64_t time = 0;
    PixelMapParams param;
    param.dstWidth = 1000;
    param.dstHeight = 200;
    auto pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);

    param.dstWidth = 500;
    param.dstHeight = 1000;
    pixelMap = helper->FetchScaledFrameYuv(time, 0, param);
    ASSERT_EQ(pixelMap->GetWidth(), 720);
    ASSERT_EQ(pixelMap->GetHeight(), 480);
}
} // namespace Media
} // namespace OHOS