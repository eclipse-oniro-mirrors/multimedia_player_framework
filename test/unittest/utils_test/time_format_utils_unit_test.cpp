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
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_001, TestSize.Level0)
{
    std::string dataTime = "";
    std::string expected = "";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario2: Test when dataTime does not contain space and does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_002, TestSize.Level0)
{
    std::string dataTime = "2022";
    std::string expected = "2022-01-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario3: Test when dataTime contains space but does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_003, TestSize.Level0)
{
    std::string dataTime = "2022 12";
    std::string expected = "2022-01-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario4: Test when dataTime contains space and contains '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_004, TestSize.Level0)
{
    std::string dataTime = "2022-12-25 12:34:56";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario5: Test when dataTime contains '-' but does not contain ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_005, TestSize.Level0)
{
    std::string dataTime = "2022-12-25";
    std::string expected = "2022-12-25 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime contains '-' and contains ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_006, TestSize.Level0)
{
    std::string dataTime = "2022-12-25 12:34:56.789";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_007, TestSize.Level0)
{
    std::string dataTime = "2022-12";
    std::string expected = "2022-12-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario6: Test when dataTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_008, TestSize.Level0)
{
    std::string dataTime = "2022-12 12:00";
    std::string expected = "2022-12-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dataTime), expected);
}

// Scenario1: Compare with manual std::put_time result
HWTEST_F(TimeFormatUtilsUnitTest, FormatLocalTime_001, TestSize.Level0)
{
    auto now = std::chrono::system_clock::now();

    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm* tm_ptr = std::localtime(&tt);
    EXPECT_NE(tm_ptr, nullptr);
    std::tm local_tm = *tm_ptr;

    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    std::string expected = oss.str();

    std::string actual = TimeFormatUtils::FormatLocalTime(now);
    EXPECT_EQ(actual, expected);
}

// Scenario2: Test epoch time (1970-01-01 00:00:00 UTC)
HWTEST_F(TimeFormatUtilsUnitTest, FormatLocalTime_002, TestSize.Level0)
{
    // 1970-01-01 00:00:00 UTC
    auto epoch = std::chrono::system_clock::time_point();
    std::string result = TimeFormatUtils::FormatLocalTime(epoch);

    EXPECT_EQ(result.length(), 19);
    int year = std::stoi(result.substr(0, 4));
    EXPECT_GE(year, 1969);
    EXPECT_LE(year, 1970);
}
} // namespace Media
} // namespace OHOS