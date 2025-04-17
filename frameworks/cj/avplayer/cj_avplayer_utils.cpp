/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cj_avplayer_utils.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CommonUtils"};
    constexpr int32_t DECIMAL = 10;
} //namespace

bool __attribute__((visibility("default"))) StrToULL(const std::string &str, uint64_t &value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front())), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    unsigned long long result = strtoull(valStr.c_str(), &end, DECIMAL);
    // end will not be nullptr here
    CHECK_AND_RETURN_RET_LOG(result <= ULLONG_MAX, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != valStr.c_str() && end[0] == '\0' && errno != ERANGE, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    value = result;
    return true;
}

char *MallocCString(const std::string &origin)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

CArrI32 Convert2CArrI32(const std::vector<int32_t> &arr)
{
    if (arr.size() == 0) {
        return CArrI32{0};
    }
    int32_t *head = static_cast<int32_t *>(malloc(sizeof(int32_t) * arr.size()));
    if (head == nullptr) {
        return CArrI32{0};
    }
    for (size_t i = 0; i < arr.size(); i++) {
        head[i] = arr[i];
    }
    return CArrI32{.head = head, .size = arr.size()};
}

CArrFloat Convert2CArrFloat(const std::vector<float> &arr)
{
    if (arr.size() == 0) {
        return CArrFloat{0};
    }
    float *head = static_cast<float *>(malloc(sizeof(float) * arr.size()));
    if (head == nullptr) {
        return CArrFloat{0};
    }
    for (size_t i = 0; i < arr.size(); i++) {
        head[i] = arr[i];
    }
    return CArrFloat{.head = head, .size = arr.size()};
}

CSubtitleInfo Convert2CSubtitleInfo(std::string text, int32_t pts, int32_t duration)
{
    CSubtitleInfo info = CSubtitleInfo{0};
    info.text = MallocCString(text);
    info.startTime = pts;
    info.duration = duration;
    return info;
}

void GetPlayerTrackIndex(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t index = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), index)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_TRACK_INDEX));
        value[count] = CValueType{.number = index, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerTrackType(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t type = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_TYPE), type)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_TRACK_TYPE));
        value[count] = CValueType{.number = type, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerMime(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    std::string mime;
    if (trackInfo.GetStringValue(std::string(PlayerKeys::PLAYER_MIME), mime)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_MIME));
        value[count] = CValueType{.number = 0, .dou = 0.0, .str = MallocCString(mime)};
        count++;
    }
}

void GetPlayerDuration(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t duration = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_DURATION), duration)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_DURATION));
        value[count] = CValueType{.number = duration, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerBitrate(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t bitrate = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_BITRATE), bitrate)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_BITRATE));
        value[count] = CValueType{.number = bitrate, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerWidth(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t width = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_WIDTH), width)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_WIDTH));
        value[count] = CValueType{.number = width, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerHeight(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t height = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_HEIGHT), height)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_HEIGHT));
        value[count] = CValueType{.number = height, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerFramerate(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    double frameRate = -1;
    if (trackInfo.GetDoubleValue(std::string(PlayerKeys::PLAYER_FRAMERATE), frameRate)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_FRAMERATE));
        value[count] = CValueType{.number = 0, .dou = frameRate, .str = nullptr};
        count++;
    }
}

void GetPlayerChannels(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t channelCount = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_CHANNELS), channelCount)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_CHANNELS));
        value[count] = CValueType{.number = channelCount, .dou = 0.0, .str = nullptr};
        count++;
    }
}

void GetPlayerSampleRate(char **key, CValueType *value, const Format trackInfo, int64_t &count)
{
    int32_t sampleRate = -1;
    if (trackInfo.GetIntValue(std::string(PlayerKeys::PLAYER_SAMPLE_RATE), sampleRate)) {
        key[count] = MallocCString(std::string(PlayerKeys::PLAYER_SAMPLE_RATE));
        value[count] = CValueType{.number = sampleRate, .dou = 0.0, .str = nullptr};
        count++;
    }
}

CMediaDescription Convert2CMediaDescription(const Format trackInfo)
{
    CMediaDescription result = CMediaDescription{0};
    char **key = static_cast<char **>(malloc(sizeof(char *) * MAX_SIZE_OF_MEDIADESCRIPTIONKEY));
    CValueType *value = static_cast<CValueType *>(malloc(sizeof(CValueType) * MAX_SIZE_OF_MEDIADESCRIPTIONKEY));
    if (key == nullptr || value == nullptr) {
        free(key);
        free(value);
        return result;
    }
    int64_t count = 0;
    GetPlayerTrackIndex(key, value, trackInfo, count);
    GetPlayerTrackType(key, value, trackInfo, count);
    GetPlayerMime(key, value, trackInfo, count);
    GetPlayerDuration(key, value, trackInfo, count);
    GetPlayerBitrate(key, value, trackInfo, count);
    GetPlayerWidth(key, value, trackInfo, count);
    GetPlayerHeight(key, value, trackInfo, count);
    GetPlayerFramerate(key, value, trackInfo, count);
    GetPlayerChannels(key, value, trackInfo, count);
    GetPlayerSampleRate(key, value, trackInfo, count);
    int32_t sampleDepth = -1;
    if (trackInfo.GetIntValue("sample_depth", sampleDepth)) {
        key[count] = MallocCString("sample_depth");
        value[count] = CValueType{.number = sampleDepth, .dou = 0.0, .str = nullptr};
        count++;
    }
    std::string language;
    if (trackInfo.GetStringValue("language", language)) {
        key[count] = MallocCString("language");
        value[count] = CValueType{.number = 0, .dou = 0.0, .str = MallocCString(language)};
        count++;
    }
    std::string trackName;
    if (trackInfo.GetStringValue("track_name", trackName)) {
        key[count] = MallocCString("track_name");
        value[count] = CValueType{.number = 0, .dou = 0.0, .str = MallocCString(trackName)};
        count++;
    }
    std::string hdrType;
    if (trackInfo.GetStringValue("hdr_type", hdrType)) {
        key[count] = MallocCString("hdr_type");
        value[count] = CValueType{.number = 0, .dou = 0.0, .str = MallocCString(hdrType)};
        count++;
    }
    result.key = key;
    result.value = value;
    result.size = count;
    return result;
}

CArrCMediaDescription Convert2CArrCMediaDescription(const std::vector<Format> trackInfo)
{
    if (trackInfo.size() == 0) {
        return CArrCMediaDescription{0};
    }
    CMediaDescription *head = static_cast<CMediaDescription *>(malloc(sizeof(CMediaDescription) * trackInfo.size()));
    if (head == nullptr) {
        return CArrCMediaDescription{0};
    }
    for (size_t i = 0; i < trackInfo.size(); i++) {
        head[i] = Convert2CMediaDescription(trackInfo[i]);
    }
    return CArrCMediaDescription{.head = head, .size = trackInfo.size()};
}
} // namespace Media
} // namespace OHOS