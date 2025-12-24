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

namespace {
    const long SEC_PER_HOUR = 3600;
    const long SEC_PER_MIN  = 60;
}

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

// Scenario1: Test when dateTime is empty
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_001, TestSize.Level0)
{
    std::string dateTime = "";
    std::string expected = "";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario2: Test when dateTime does not contain space and does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_002, TestSize.Level0)
{
    std::string dateTime = "2022";
    std::string expected = "2022-01-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario3: Test when dateTime contains space but does not contain '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_003, TestSize.Level0)
{
    std::string dateTime = "2022 12";
    std::string expected = "2022-01-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario4: Test when dateTime contains space and contains '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_004, TestSize.Level0)
{
    std::string dateTime = "2022-12-25 12:34:56";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario5: Test when dateTime contains '-' but does not contain ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_005, TestSize.Level0)
{
    std::string dateTime = "2022-12-25";
    std::string expected = "2022-12-25 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario6: Test when dateTime contains '-' and contains ':'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_006, TestSize.Level0)
{
    std::string dateTime = "2022-12-25 12:34:56.789";
    std::string expected = "2022-12-25 12:34:56";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario6: Test when dateTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_007, TestSize.Level0)
{
    std::string dateTime = "2022-12";
    std::string expected = "2022-12-01 00:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

// Scenario6: Test when dateTime first '-' =  last '-'
HWTEST_F(TimeFormatUtilsUnitTest, FormatDateTimeByString_008, TestSize.Level0)
{
    std::string dateTime = "2022-12 12:00";
    std::string expected = "2022-12-01 12:00:00";
    EXPECT_EQ(TimeFormatUtils::FormatDateTimeByString(dateTime), expected);
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_001, TestSize.Level0)
{
    // Empty or Z → 0
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset(""), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("Z"), 0L);
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_002, TestSize.Level0)
{
    // Invalid symbol
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("X0800"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("@08:00"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("0800"), 0L); // missing +/- 
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_003, TestSize.Level0)
{
    // Valid +HH:MM
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+08:00"), 8 * SEC_PER_HOUR);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("-05:30"), -(5 * SEC_PER_HOUR + 30 * SEC_PER_MIN));
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+00:00"), 0L);
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_004, TestSize.Level0)
{
    // Invalid +H:M or truncated
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+8:0"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+08:"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+0:00"), 0L); // 长度不够
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+08:0"), 0L); // mins only 1 digit
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_005, TestSize.Level0)
{
    // Valid +HHMM (4-digit)
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+0800"), 8 * SEC_PER_HOUR);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("-1234"), -(12 * SEC_PER_HOUR + 34 * SEC_PER_MIN));
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+0000"), 0L);
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_006, TestSize.Level0)
{
    // Invalid HHMM (not 4-digit)
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+08"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+080"), 0L);
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+08000"), 0L); // too long
}

HWTEST_F(TimeFormatUtilsUnitTest, ParseIso8601TimeZoneOffset_007, TestSize.Level0)
{
    // Extreme but valid values
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+1400"), 14 * SEC_PER_HOUR); // max UTC+14
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("-1200"), -12 * SEC_PER_HOUR); // min common
    // Note: "+9999" is parsed as 99h99m, though invalid in real world
    long extreme = (99 * 60 + 99) * 60;
    EXPECT_EQ(TimeFormatUtils::ParseIso8601TimeZoneOffset("+9999"), extreme);
}
} // namespace Media
} // namespace OHOS