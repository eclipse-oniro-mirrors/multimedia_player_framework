/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#include "gtest/gtest.h"
#include "time_format_utils_unit_test.h"


#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void TimeFormatUtilsUnitTest::SetUpTestCase(void) {}

void TimeFormatUtilsUnitTest::TearDownTestCase(void) {}

void TimeFormatUtilsUnitTest::SetUp(void) {}

void TimeFormatUtilsUnitTest::TearDown(void) {}

// Scenario1: Test standard ISO8601 type string
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_001, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01:01:01Z";
    std::string expected = "2023-01";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str).substr(0, 7), expected);
}

// Scenario2: Test non-standard ISO8601 type string
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_002, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01 01:01:01";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario3: Test compare("Z")
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_003, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T23:01:01";
    std::string expected = "2023-01";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str).substr(0, 7), expected);
}

// Scenario4: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_004, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T24:01:01Z";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario5: Test ISO8601 type string with no timezone
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_005, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01:01:01.123";
    std::string expected = "2023-01-01 01:01:01";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), expected);
}

// Scenario6: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_006, TestSize.Level0) {
    std::string iso8601Str = "023-01-01T01:01:01.123";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario7: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_007, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario8: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_008, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01.01.01.123";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario9: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_009, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01:01:01.123+0800Z";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario10: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_010, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01:01:01.123+08";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario11: Test ISO8601 type string with invalid time
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByTimeZone_011, TestSize.Level0) {
    std::string iso8601Str = "2023-01-01T01:01:01.123+0800T";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByTimeZone(iso8601Str), iso8601Str);
}

// Scenario1: Test when dataTime is empty
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_001, TestSize.Level0)
{
    std::string dataTime = "";
    std::string expected = "";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario2: Test when dataTime does not contain space and does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_002, TestSize.Level0)
{
    std::string dataTime = "2022";
    std::string expected = "2022-01-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario3: Test when dataTime contains space but does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_003, TestSize.Level0)
{
    std::string dataTime = "2022 12";
    std::string expected = "2022-01-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario4: Test when dataTime contains space and contains '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_004, TestSize.Level0)
{
    std::string dataTime = "2022-12-25 12:34:56";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario5: Test when dataTime contains '-' but does not contain ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_005, TestSize.Level0)
{
    std::string dataTime = "2022-12-25";
    std::string expected = "2022-12-25 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime contains '-' and contains ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_006, TestSize.Level0)
{
    std::string dataTime = "2022-12-25 12:34:56.789";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_007, TestSize.Level0)
{
    std::string dataTime = "2022-12";
    std::string expected = "2022-12-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDataTimeByString_008, TestSize.Level0)
{
    std::string dataTime = "2022-12 12:00";
    std::string expected = "2022-12-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDataTimeByString(dataTime), expected);
}
} // namespace Media
} // namespace OHOS