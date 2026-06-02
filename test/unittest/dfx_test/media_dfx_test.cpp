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

#ifndef CROSS_PLATFORM
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

// Scenario7: Test case for float type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseFloat_WhenFloatType, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    float value = 0.5f;
    listPair.second->SetData(Tag::MEDIA_LATITUDE, value);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);
    Any valueType = OHOS::Media::GetDefaultAnyValue(Tag::MEDIA_LATITUDE);
    EXPECT_EQ(Any::IsSameTypeWith<float>(valueType), true);
    EXPECT_EQ(metaInfoJson[Tag::MEDIA_LATITUDE], "0.50");
}

// Scenario8: Test case for default type
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParsedefault_WhendefaultType, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    float value = 0.5f;
    listPair.second->SetData(Tag::VIDEO_BIT_STREAM_FORMAT, value);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);
    Any valueType = OHOS::Media::GetDefaultAnyValue(Tag::VIDEO_BIT_STREAM_FORMAT);
    EXPECT_EQ(Any::IsSameTypeWith<float>(valueType), false);
}

// Scenario9: Test case for uint64_t type repeat
HWTEST_F(MediaDfxTest, ParseOneEvent_ShouldParseUint64_WhenUint64Type_002, TestSize.Level0) {
    std::pair<uint64_t, std::shared_ptr<Meta>> listPair;
    listPair.first = 1;
    listPair.second = std::make_shared<Meta>();
    listPair.second->SetData(Tag::MEDIA_FILE_SIZE, 123u);
    listPair.second->SetData(Tag::MEDIA_POSITION, 123u);
    listPair.second->SetData(Tag::AV_PLAYER_DOWNLOAD_TOTAL_BITS, 123u);
    json metaInfoJson;

    mediaEvent_->ParseOneEvent(listPair, metaInfoJson);
    Any valueType = OHOS::Media::GetDefaultAnyValue(Tag::MEDIA_FILE_SIZE);
    EXPECT_EQ(Any::IsSameTypeWith<uint64_t>(valueType), true);
    valueType = OHOS::Media::GetDefaultAnyValue(Tag::AV_PLAYER_DOWNLOAD_TOTAL_BITS);
    EXPECT_EQ(Any::IsSameTypeWith<uint64_t>(valueType), true);
    valueType = OHOS::Media::GetDefaultAnyValue(Tag::MEDIA_POSITION);
    EXPECT_EQ(Any::IsSameTypeWith<uint64_t>(valueType), true);
}
#endif

// Scenario10: Test case for BehaviorEventWrite
HWTEST_F(MediaDfxTest, ParseOneEvent_BehaviorEventWrite, TestSize.Level0) {
    std::string status = "testMeg1";
    std::string module = "testmodule";
    BehaviorEventWrite(status, module);
    std::string testvalue = "state change, current state is: testMeg1";
    bool ret = mediaEvent_->CreateMsg("state change, current state is: testMeg1");
    EXPECT_NE(ret, false);
    EXPECT_EQ(mediaEvent_->msg_, testvalue);
}

// Scenario11: Test case for BehaviorEventWriteForScreenCapture
HWTEST_F(MediaDfxTest, ParseOneEvent_BehaviorEventWriteForScreenCapture, TestSize.Level0) {
    std::string status = "testMeg2";
    std::string module = "testmodule";
    int32_t appUid = 10;
    int32_t appPid = 11;
    BehaviorEventWriteForScreenCapture(status, module, appUid, appPid);
    std::string testvalue = "state change, current state is: testMeg2";
    bool ret = mediaEvent_->CreateMsg("state change, current state is: testMeg2");
    EXPECT_NE(ret, false);
    EXPECT_EQ(mediaEvent_->msg_, testvalue);
}

// Scenario12: Test case for StatisticEventWriteBundleName
HWTEST_F(MediaDfxTest, ParseOneEvent_StatisticEventWriteBundleName, TestSize.Level0) {
    std::string status = "testMeg3";
    std::string module = "testmodule";
    std::string bundleName = "";
    StatisticEventWriteBundleName(status, module, bundleName);
    std::string testvalue = "state change, current state is: testMeg3";
    bool ret = mediaEvent_->CreateMsg("state change, current state is: testMeg3");
    EXPECT_NE(ret, false);
    EXPECT_EQ(mediaEvent_->msg_, testvalue);
}

HWTEST_F(MediaDfxTest, RecordSubtitleCbRegister_001, TestSize.Level0) {
    uint64_t instanceId = 100;
    int32_t state = 4;
    int32_t ret = RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, state);
    EXPECT_EQ(ret, MSERR_OK);
    ret = RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, state);
    EXPECT_EQ(ret, MSERR_OK);
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    json result = BuildSubtitleCbStatsJson(CallType::AVPLAYER, TEST_UID_ID_1);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result[0]["registerCountByState"][std::to_string(state)], 2);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, RecordSubtitleCbUnregister_001, TestSize.Level0) {
    uint64_t instanceId = 101;
    int32_t state = 4;
    int32_t ret = RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, state);
    EXPECT_EQ(ret, MSERR_OK);
    ret = RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, state);
    EXPECT_EQ(ret, MSERR_OK);
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    json result = BuildSubtitleCbStatsJson(CallType::AVPLAYER, TEST_UID_ID_1);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result[0]["unregisterCountByState"][std::to_string(state)], 2);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, RecordSubtitleCbRegister_Unregister_001, TestSize.Level0) {
    uint64_t instanceId = 102;
    int32_t regState = 2;
    int32_t unregState = 4;
    int32_t ret = RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, regState);
    EXPECT_EQ(ret, MSERR_OK);
    ret = RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, unregState);
    EXPECT_EQ(ret, MSERR_OK);
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    json result = BuildSubtitleCbStatsJson(CallType::AVPLAYER, TEST_UID_ID_1);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result[0]["registerCountByState"][std::to_string(regState)], 1);
    EXPECT_EQ(result[0]["unregisterCountByState"][std::to_string(unregState)], 1);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, RecordSubtitleCbRegister_MultipleStates, TestSize.Level0) {
    uint64_t instanceId = 200;
    int32_t ret = RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 2);
    EXPECT_EQ(ret, MSERR_OK);
    ret = RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    EXPECT_EQ(ret, MSERR_OK);
    auto it = subtitleCbCounterMap_.find(instanceId);
    ASSERT_NE(it, subtitleCbCounterMap_.end());
    EXPECT_EQ(it->second.registerCountByState[2], 1);
    EXPECT_EQ(it->second.registerCountByState[4], 1);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, RecordSubtitleCbUnregister_MultipleStates, TestSize.Level0) {
    uint64_t instanceId = 201;
    int32_t ret = RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 2);
    EXPECT_EQ(ret, MSERR_OK);
    ret = RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    EXPECT_EQ(ret, MSERR_OK);
    auto it = subtitleCbCounterMap_.find(instanceId);
    ASSERT_NE(it, subtitleCbCounterMap_.end());
    EXPECT_EQ(it->second.unregisterCountByState[2], 1);
    EXPECT_EQ(it->second.unregisterCountByState[4], 1);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, CollectSubtitleCbCounter_FoundInMap, TestSize.Level0) {
    uint64_t instanceId = 300;
    RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    ASSERT_NE(subtitleCbCounterMap_.find(instanceId), subtitleCbCounterMap_.end());
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    EXPECT_EQ(subtitleCbCounterMap_.find(instanceId), subtitleCbCounterMap_.end());
    ASSERT_NE(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    ASSERT_NE(reportSubtitleCbCounterMap_[CallType::AVPLAYER].find(TEST_UID_ID_1),
        reportSubtitleCbCounterMap_[CallType::AVPLAYER].end());
    EXPECT_EQ(reportSubtitleCbCounterMap_[CallType::AVPLAYER][TEST_UID_ID_1].size(), 1);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, CollectSubtitleCbCounter_NotFoundInMap, TestSize.Level0) {
    uint64_t instanceId = 301;
    EXPECT_EQ(subtitleCbCounterMap_.find(instanceId), subtitleCbCounterMap_.end());
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    EXPECT_EQ(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, BuildSubtitleCbStatsJson_CallTypeNotFound, TestSize.Level0) {
    reportSubtitleCbCounterMap_[CallType::AVRECORDER] = {};
    json result = BuildSubtitleCbStatsJson(CallType::AVRECORDER, TEST_UID_ID_1);
    EXPECT_TRUE(result.empty());
    result = BuildSubtitleCbStatsJson(CallType::AVRECORDER, 999);
    EXPECT_TRUE(result.empty());
    result = BuildSubtitleCbStatsJson(CallType::METADATA_RETRIEVER, TEST_UID_ID_1);
    EXPECT_TRUE(result.empty());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, BuildSubtitleCbStatsJson_UidNotFound, TestSize.Level0) {
    reportSubtitleCbCounterMap_[CallType::AVPLAYER] = {};
    json result = BuildSubtitleCbStatsJson(CallType::AVPLAYER, TEST_UID_ID_1);
    EXPECT_TRUE(result.empty());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

#ifndef CROSS_PLATFORM
HWTEST_F(MediaDfxTest, BuildSubtitleCbStatsJson_HasData, TestSize.Level0) {
    uint64_t instanceId = 400;
    RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 2);
    RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    RecordSubtitleCbUnregister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    json result = BuildSubtitleCbStatsJson(CallType::AVPLAYER, TEST_UID_ID_1);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.size(), 1);
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, SetSubtitleCbStats_EmptyStats, TestSize.Level0) {
    json eventInfoJson;
    reportSubtitleCbCounterMap_[CallType::AVRECORDER] = {};
    mediaEvent_->SetSubtitleCbStats(CallType::AVRECORDER, TEST_UID_ID_1, eventInfoJson);
    EXPECT_TRUE(eventInfoJson.find("subtitleCbStats") == eventInfoJson.end());
    mediaEvent_->SetSubtitleCbStats(CallType::AVPLAYER, TEST_UID_ID_1, eventInfoJson);
    EXPECT_TRUE(eventInfoJson.find("subtitleCbStats") == eventInfoJson.end());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, SetSubtitleCbStats_NonEmptyStats, TestSize.Level0) {
    uint64_t instanceId = 401;
    RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    CollectSubtitleCbCounter(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    json eventInfoJson;
    mediaEvent_->SetSubtitleCbStats(CallType::AVPLAYER, TEST_UID_ID_1, eventInfoJson);
    EXPECT_TRUE(eventInfoJson.find("subtitleCbStats") != eventInfoJson.end());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}
#endif

HWTEST_F(MediaDfxTest, CollectReportMediaInfo_WithSubtitleData, TestSize.Level0) {
    uint64_t instanceId = 500;
    int32_t ret = CreateMediaInfo(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    ASSERT_EQ(ret, MSERR_OK);
    RecordSubtitleCbRegister(CallType::AVPLAYER, TEST_UID_ID_1, instanceId, 4);
    ASSERT_NE(subtitleCbCounterMap_.find(instanceId), subtitleCbCounterMap_.end());
    ret = ReportMediaInfo(instanceId);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_NE(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, CollectReportMediaInfo_NoSubtitleData, TestSize.Level0) {
    uint64_t instanceId = 501;
    int32_t ret = CreateMediaInfo(CallType::AVPLAYER, TEST_UID_ID_1, instanceId);
    ASSERT_EQ(ret, MSERR_OK);
    EXPECT_EQ(subtitleCbCounterMap_.find(instanceId), subtitleCbCounterMap_.end());
    ret = ReportMediaInfo(instanceId);
    ASSERT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    subtitleCbCounterMap_.clear();
    reportSubtitleCbCounterMap_.clear();
}

HWTEST_F(MediaDfxTest, StatisticsEventReport_ClearsSubtitleReportMap, TestSize.Level0) {
    reportMediaInfoMap_[CallType::AVPLAYER][TEST_UID_ID_1] = {};
    SubtitleCbStateCounter counter;
    counter.appName = "test";
    counter.uid = TEST_UID_ID_1;
    counter.instanceId = 600;
    counter.registerCountByState[4] = 1;
    reportSubtitleCbCounterMap_[CallType::AVPLAYER][TEST_UID_ID_1].push_back(counter);
    ASSERT_NE(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    int32_t result = StatisticsEventReport();
    ASSERT_EQ(result, MSERR_OK);
    EXPECT_EQ(reportSubtitleCbCounterMap_.find(CallType::AVPLAYER), reportSubtitleCbCounterMap_.end());
    reportMediaInfoMap_.clear();
}
}
}