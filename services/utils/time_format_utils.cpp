/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#include "time_format_utils.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "TimeFormatUtils"};
}

namespace OHOS {
namespace Media {
std::string TimeFormatUtils::FormatDateTimeByTimeZone(const std::string &iso8601Str)
{
    if (iso8601Str.empty()) {
        return iso8601Str;
    }
    std::regex pattern(
        R"((\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(((\+|-)\d{4})|Z|((\+|-)\d{2}:\d{2}))?)");
    std::smatch match;
    if (!std::regex_match(iso8601Str, match, pattern)) {
        return iso8601Str;  // not standard ISO8601 type string
    }

    std::istringstream iss(iso8601Str);
    std::tm tm{.tm_isdst = -1};
    if (!(iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S"))) {
        return iso8601Str;  // cant prase time
    }

    // time zone
    time_t tt = mktime(&tm);
    if (tt == -1) {
        return iso8601Str;
    }
    uint32_t length = iso8601Str.length();
    long diffTime = 0;
    std::string tz = (match.size() > 8) ? match[8].str();
    if (tz.empty()) {
        return FormatLocalTime(std::chrono::system_clock::from_time_t(tt));
    }
    if (tz.compare("Z") != 0) {
        diffTime = ParseIso8601TimeZoneOffset(tz);
    }

    // convert time to localtime
    long timezone = 0;
    std::tm *timeWithOffsetPtr = localtime(&tt);
    if (timeWithOffsetPtr == nullptr) {
        return "";
    }
    std::tm timeWithOffset = *timeWithOffsetPtr;
    if (timeWithOffset.tm_gmtoff != 0) {
        timezone = timeWithOffset.tm_gmtoff;
    }
    auto localTime =
        std::chrono::system_clock::from_time_t(std::mktime(&tm)) + std::chrono::seconds(timezone - diffTime);
    return FormatLocalTime(localTime);
}

long TimeFormatUtils::ParseIso8601TimeZoneOffset(const std::string& tz) {
    if (tz.empty() || tz == "Z") {
        return 0;
    }

    char symbol = tz[0];
    if (symbol != '+' && symbol != '-') {
        return 0;
    }

    std::string numPart = tz.substr(1);
    int hours = 0, mins = 0;

    if (numPart.find(':') != std::string::npos) {
        if (numPart.length() < 5 || numPart[2] != ':') {
            return 0;
        }
        hours = std::stoi(numPart.substr(0, 2));
        mins  = std::stoi(numPart.substr(3, 2));
    } else {
        if (numPart.length() != 4) {
            return 0;
        }
        hours = std::stoi(numPart.substr(0, 2));
        mins  = std::stoi(numPart.substr(2, 2));
    }

    long seconds = (hours * 60 + mins) * 60;
    return (symbol == '+') ? seconds : -seconds;
}

std::string TimeFormatUtils::FormatLocalTime(std::chrono::system_clock::time_point localTime)
{
    std::time_t localTimeT = std::chrono::system_clock::to_time_t(localTime);
    std::tm *localTmPtr = std::localtime(&localTimeT);
    if (localTmPtr == nullptr) {
        return "";
    }
    std::tm localTm = *localTmPtr;
    std::ostringstream oss;
    oss << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string TimeFormatUtils::FormatDateTimeByString(const std::string &dateTime)
{
    if (dateTime.compare("") == 0) {
        return dateTime;
    }
    std::string::size_type position = dateTime.find(" ");
    std::string date = "";
    std::string time = "";
    if (position == dateTime.npos) {
        date = dateTime;
        if (date.find("-") == date.npos) {
            date += "-01-01";
        } else if (date.find_first_of("-") == date.find_last_of("-")) {
            date += "-01";
        }
        time += " 00:00:00";
    } else {
        date = dateTime.substr(0, position);
        time = dateTime.substr(position);
        if (date.find("-") == date.npos) {
            date += "-01-01";
        } else if (date.find_first_of("-") == date.find_last_of("-")) {
            date += "-01";
        }
        if (time.find(":") == time.npos) {
            time += ":00:00";
        } else if (time.find_first_of(":") == time.find_last_of(":")) {
            time += ":00";
        } else {
            time = time.substr(0, time.find("."));
        }
    }
    MEDIA_LOGD("FormatDateTimeByString is: %{public}s%{public}s", date.c_str(), time.c_str());
    return date + time;
}
}  // namespace Media
}  // namespace OHOS