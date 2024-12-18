/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <memory>
#include <iostream>
#include "gtest/gtest.h"
#include "media_dfx.cpp"
#include "common/media_core.h"
#include "meta/meta.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace {
    constexpr uint32_t TEST_UID_ID_1 = 1;
    constexpr int32_t ERROR_CODE = 5;
}

namespace OHOS {
namespace Media {
class MediaDfxTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        mediaEvent_ = std::make_shared<MediaEvent>();
    };
    void TearDown(void)
    {
        mediaEvent_ = nullptr;
    };

    std::shared_ptr<MediaEvent> mediaEvent_ = nullptr;
};

HWTEST_F(MediaDfxTest, CREATE_MEDIA_INFO, TestSize.Level1)
{
    uint64_t instanceId = 1;
    int32_t ret = CreateMediaInfo(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_MSG, "SCREEN_CAPTURE_ERR_MSG");
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_CODE, ERROR_CODE);
    ret = AppendMediaInfo(meta, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    ret = ReportMediaInfo(instanceId);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(MediaDfxTest, CREATE_MEDIA_INFO_1, TestSize.Level1)
{
    uint64_t instanceId = 1;
    int32_t ret = CreateMediaInfo(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_MSG, "SCREEN_CAPTURE_ERR_MSG");
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_CODE, ERROR_CODE);
    ret = AppendMediaInfo(meta, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    ret = AppendMediaInfo(meta1, instanceId);
    ASSERT_NE(ret, MSERR_OK);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);

    ret = ReportMediaInfo(instanceId);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(MediaDfxTest, CREATE_MEDIA_INFO_2, TestSize.Level1)
{
    uint64_t instanceId = 1;
    int32_t ret = CreateMediaInfo(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_MSG, "SCREEN_CAPTURE_ERR_MSG");
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_CODE, ERROR_CODE);
    ret = AppendMediaInfo(meta, instanceId);
    ASSERT_EQ(ret, MSERR_OK);

    ret = ReportMediaInfo(instanceId);
    ASSERT_EQ(ret, MSERR_OK);
    ret = ReportMediaInfo(instanceId);
    ASSERT_NE(ret, MSERR_OK);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(MediaDfxTest, StatisticsEventReport_ShouldReturnError_WhenMapIsEmpty, TestSize.Level0)
{
    reportMediaInfoMap_.clear();
    int32_t result = StatisticsEventReport();
    ASSERT_EQ(result, OHOS::Media::MSERR_INVALID_OPERATION);
}

// Test when reportMediaInfoMap_ is not empty, StatisticsEventReport should return MSERR_OK
HWTEST_F(MediaDfxTest, StatisticsEventReport_ShouldReturnSuccess_WhenMapIsNotEmpty_001, TestSize.Level0)
{
    reportMediaInfoMap_[OHOS::Media::CallType::AVPLAYER] = {};
    int32_t result = StatisticsEventReport();
    ASSERT_EQ(result, OHOS::Media::MSERR_OK);
    reportMediaInfoMap_.clear();
}

// Test when reportMediaInfoMap_ is not empty, StatisticsEventReport should return MSERR_OK
HWTEST_F(MediaDfxTest, StatisticsEventReport_ShouldReturnSuccess_WhenMapIsNotEmpty_002, TestSize.Level0)
{
    int32_t uid = 123;
    reportMediaInfoMap_[OHOS::Media::CallType::AVPLAYER][uid] = {};
    int32_t result = StatisticsEventReport();
    ASSERT_EQ(result, OHOS::Media::MSERR_OK);
    reportMediaInfoMap_.clear();
}

#ifdef SUPPORT_JSON
// Scenario1: Test case for int32_t type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseInt32_WhenInt32Type, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::APP_UID, 123);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);

    EXPECT_EQ(metaInfoJson[Tag::APP_UID], "123");
}

// Scenario2: Test case for uint32_t type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseUint32_WhenUint32Type, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::DRM_DECRYPT_AVG_SIZE, 456u);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);

    EXPECT_EQ(metaInfoJson[Tag::DRM_DECRYPT_AVG_SIZE], "456");
}

// Scenario3: Test case for uint64_t type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseUint64_WhenUint64Type, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::AV_PLAYER_DOWNLOAD_TOTAL_BITS, 789u);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);
    Any valueType = OHOS::Media::GetDefaultAnyValue(Tag::AV_PLAYER_DOWNLOAD_TOTAL_BITS);
    EXPECT_EQ(Any::IsSameTypeWith<uint64_t>(valueType), true);
}

// Scenario4: Test case for string type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseString_WhenStringType, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::MIME_TYPE, "test");
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);

    EXPECT_EQ(metaInfoJson[Tag::MIME_TYPE], "test");
}

// Scenario5: Test case for int8_t type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseInt8_WhenInt8Type, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    int8_t value = 100;
    listPair.second->SetData(Tag::AV_PLAYER_HDR_TYPE, value);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);
    Any valueType = OHOS::Media::GetDefaultAnyValue(Tag::AV_PLAYER_HDR_TYPE);
    EXPECT_EQ(Any::IsSameTypeWith<int8_t>(valueType), true);
}

// Scenario6: Test case for bool type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseBool_WhenBoolType, TestSize.Level0) {

    // test StatisicsHiSysEventWrite
    std::vector<std::string> infoArr = {"test for tdd", "test for tdd"};
    mediaEvent_->StatisicsHiSysEventWrite(CallType::AVPLAYER, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, infoArr);
    mediaEvent_->StatisicsHiSysEventWrite(CallType::AVRECORDER, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, infoArr);
    mediaEvent_->StatisicsHiSysEventWrite(CallType::SCREEN_CAPTRUER,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, infoArr);
    mediaEvent_->StatisicsHiSysEventWrite(CallType::AVTRANSCODER,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, infoArr);
    mediaEvent_->StatisicsHiSysEventWrite(CallType::METADATA_RETRIEVER,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, infoArr);
    
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::MEDIA_HAS_VIDEO, true);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);

    EXPECT_EQ(metaInfoJson[Tag::MEDIA_HAS_VIDEO], "true");
}
#endif
}
}