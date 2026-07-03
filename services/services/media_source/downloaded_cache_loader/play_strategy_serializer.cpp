/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "play_strategy_serializer.h"
#include "media_source.h"
#include "media_log.h"
#include <cstring>

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "PlayStrategySerializer" };
}

namespace OHOS {
namespace Media {
namespace DownloadedCache {

namespace {
void WriteUint32(std::vector<uint8_t>& buffer, uint32_t value)
{
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(uint32_t));
}

void WriteInt32(std::vector<uint8_t>& buffer, int32_t value)
{
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(int32_t));
}

void WriteDouble(std::vector<uint8_t>& buffer, double value)
{
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(double));
}

void WriteBool(std::vector<uint8_t>& buffer, bool value)
{
    uint8_t val = value ? 1 : 0;
    buffer.push_back(val);
}

void WriteString(std::vector<uint8_t>& buffer, const std::string& str)
{
    uint32_t len = static_cast<uint32_t>(str.size());
    WriteUint32(buffer, len);
    if (len > 0) {
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
}

uint32_t ReadUint32(const std::vector<uint8_t>& buffer, size_t& offset)
{
    uint32_t value = 0;
    errno_t ret = memcpy_s(&value, sizeof(uint32_t), buffer.data() + offset, sizeof(uint32_t));
    if (ret != EOK) {
        MEDIA_LOGE("ReadUint32 memcpy_s failed");
        offset += sizeof(uint32_t);
        return 0;
    }
    offset += sizeof(uint32_t);
    return value;
}

int32_t ReadInt32(const std::vector<uint8_t>& buffer, size_t& offset)
{
    int32_t value = 0;
    errno_t ret = memcpy_s(&value, sizeof(int32_t), buffer.data() + offset, sizeof(int32_t));
    if (ret != EOK) {
        MEDIA_LOGE("ReadInt32 memcpy_s failed");
        offset += sizeof(int32_t);
        return 0;
    }
    offset += sizeof(int32_t);
    return value;
}

double ReadDouble(const std::vector<uint8_t>& buffer, size_t& offset)
{
    double value = 0;
    errno_t ret = memcpy_s(&value, sizeof(double), buffer.data() + offset, sizeof(double));
    if (ret != EOK) {
        MEDIA_LOGE("ReadDouble memcpy_s failed");
        offset += sizeof(double);
        return 0;
    }
    offset += sizeof(double);
    return value;
}

bool ReadBool(const std::vector<uint8_t>& buffer, size_t& offset)
{
    uint8_t value = buffer[offset];
    offset += sizeof(uint8_t);
    return value != 0;
}

std::string ReadString(const std::vector<uint8_t>& buffer, size_t& offset)
{
    uint32_t len = ReadUint32(buffer, offset);
    if (len == 0) {
        return "";
    }
    std::string str(buffer.begin() + offset, buffer.begin() + offset + len);
    offset += len;
    return str;
}
}

size_t CalculateStringSize(const std::string& str)
{
    return sizeof(uint32_t) + str.size();
}

size_t CalculatePlayStrategySize(const std::string& rootUrl, const Plugins::PlayStrategy& strategy)
{
    size_t size = 0;
    size += CalculateStringSize(rootUrl);
    size += sizeof(uint32_t);  // width
    size += sizeof(uint32_t);  // height
    size += sizeof(uint32_t);  // duration
    size += sizeof(uint8_t);    // preferHDR
    size += CalculateStringSize(strategy.audioLanguage);
    size += CalculateStringSize(strategy.subtitleLanguage);
    size += sizeof(double);  // bufferDurationForPlaying
    size += sizeof(double);  // thresholdForAutoQuickPlay
    return size;
}

size_t CalculateTrackSelectionFilterSize(const Plugins::TrackSelectionFilter& filter)
{
    size_t size = 0;
    size += sizeof(int32_t);   // maxVideoBitrate
    size += sizeof(int32_t);   // minVideoBitrate
    size += sizeof(int32_t);   // maxVideoFrameRate
    size += sizeof(int32_t);   // minVideoFrameRate
    size += sizeof(int32_t);   // maxVideoResolution.first
    size += sizeof(int32_t);   // maxVideoResolution.second
    size += sizeof(int32_t);   // minVideoResolution.first
    size += sizeof(int32_t);   // minVideoResolution.second
    size += sizeof(uint32_t);  // preferredVideoMimeTypes count
    for (const auto& mime : filter.preferredVideoMimeTypes) {
        size += CalculateStringSize(mime);
    }
    size += sizeof(int32_t);   // maxAudioBitrate
    size += sizeof(int32_t);   // minAudioBitrate
    size += sizeof(int32_t);   // maxAudioChannels
    size += sizeof(uint32_t);  // preferredAudioMimeTypes count
    for (const auto& mime : filter.preferredAudioMimeTypes) {
        size += CalculateStringSize(mime);
    }
    size += sizeof(uint32_t);  // preferredAudioLanguages count
    for (const auto& lang : filter.preferredAudioLanguages) {
        size += CalculateStringSize(lang);
    }
    size += sizeof(uint32_t);  // preferredSubtitleLanguages count
    for (const auto& lang : filter.preferredSubtitleLanguages) {
        size += CalculateStringSize(lang);
    }
    return size;
}

bool PlayStrategySerializer::Serialize(const std::string& rootUrl,
                                       const Plugins::PlayStrategy& strategy,
                                       const Plugins::TrackSelectionFilter& filter,
                                       std::vector<uint8_t>& output)
{
    size_t totalSize = CalculatePlayStrategySize(rootUrl, strategy) + CalculateTrackSelectionFilterSize(filter);
    output.clear();
    output.reserve(totalSize);

    WriteString(output, rootUrl);
    WriteUint32(output, strategy.width);
    WriteUint32(output, strategy.height);
    WriteUint32(output, strategy.duration);
    WriteBool(output, strategy.preferHDR);
    WriteString(output, strategy.audioLanguage);
    WriteString(output, strategy.subtitleLanguage);
    WriteDouble(output, strategy.bufferDurationForPlaying);
    WriteDouble(output, strategy.thresholdForAutoQuickPlay);

    WriteInt32(output, filter.maxVideoBitrate);
    WriteInt32(output, filter.minVideoBitrate);
    WriteInt32(output, filter.maxVideoFrameRate);
    WriteInt32(output, filter.minVideoFrameRate);
    WriteInt32(output, filter.maxVideoResolution.first);
    WriteInt32(output, filter.maxVideoResolution.second);
    WriteInt32(output, filter.minVideoResolution.first);
    WriteInt32(output, filter.minVideoResolution.second);

    WriteUint32(output, static_cast<uint32_t>(filter.preferredVideoMimeTypes.size()));
    for (const auto& mime : filter.preferredVideoMimeTypes) {
        WriteString(output, mime);
    }

    WriteInt32(output, filter.maxAudioBitrate);
    WriteInt32(output, filter.minAudioBitrate);
    WriteInt32(output, filter.maxAudioChannels);

    WriteUint32(output, static_cast<uint32_t>(filter.preferredAudioMimeTypes.size()));
    for (const auto& mime : filter.preferredAudioMimeTypes) {
        WriteString(output, mime);
    }

    WriteUint32(output, static_cast<uint32_t>(filter.preferredAudioLanguages.size()));
    for (const auto& lang : filter.preferredAudioLanguages) {
        WriteString(output, lang);
    }

    WriteUint32(output, static_cast<uint32_t>(filter.preferredSubtitleLanguages.size()));
    for (const auto& lang : filter.preferredSubtitleLanguages) {
        WriteString(output, lang);
    }

    return true;
}

bool PlayStrategySerializer::Deserialize(const std::vector<uint8_t>& input,
                                         std::string& rootUrl,
                                         Plugins::PlayStrategy& strategy,
                                         Plugins::TrackSelectionFilter& filter)
{
    if (input.empty()) {
        MEDIA_LOGE("Input buffer is empty");
        return false;
    }

    size_t offset = 0;

    rootUrl = ReadString(input, offset);
    strategy.width = ReadUint32(input, offset);
    strategy.height = ReadUint32(input, offset);
    strategy.duration = ReadUint32(input, offset);
    strategy.preferHDR = ReadBool(input, offset);
    strategy.audioLanguage = ReadString(input, offset);
    strategy.subtitleLanguage = ReadString(input, offset);
    strategy.bufferDurationForPlaying = ReadDouble(input, offset);
    strategy.thresholdForAutoQuickPlay = ReadDouble(input, offset);

    filter.maxVideoBitrate = ReadInt32(input, offset);
    filter.minVideoBitrate = ReadInt32(input, offset);
    filter.maxVideoFrameRate = ReadInt32(input, offset);
    filter.minVideoFrameRate = ReadInt32(input, offset);
    filter.maxVideoResolution.first = ReadInt32(input, offset);
    filter.maxVideoResolution.second = ReadInt32(input, offset);
    filter.minVideoResolution.first = ReadInt32(input, offset);
    filter.minVideoResolution.second = ReadInt32(input, offset);

    uint32_t videoMimeCount = ReadUint32(input, offset);
    filter.preferredVideoMimeTypes.resize(videoMimeCount);
    for (uint32_t i = 0; i < videoMimeCount; ++i) {
        filter.preferredVideoMimeTypes[i] = ReadString(input, offset);
    }

    filter.maxAudioBitrate = ReadInt32(input, offset);
    filter.minAudioBitrate = ReadInt32(input, offset);
    filter.maxAudioChannels = ReadInt32(input, offset);

    uint32_t audioMimeCount = ReadUint32(input, offset);
    filter.preferredAudioMimeTypes.resize(audioMimeCount);
    for (uint32_t i = 0; i < audioMimeCount; ++i) {
        filter.preferredAudioMimeTypes[i] = ReadString(input, offset);
    }

    uint32_t audioLangCount = ReadUint32(input, offset);
    filter.preferredAudioLanguages.resize(audioLangCount);
    for (uint32_t i = 0; i < audioLangCount; ++i) {
        filter.preferredAudioLanguages[i] = ReadString(input, offset);
    }

    uint32_t subtitleLangCount = ReadUint32(input, offset);
    filter.preferredSubtitleLanguages.resize(subtitleLangCount);
    for (uint32_t i = 0; i < subtitleLangCount; ++i) {
        filter.preferredSubtitleLanguages[i] = ReadString(input, offset);
    }

    return true;
}

bool PlayStrategySerializer::WriteToFile(std::ofstream& file,
                                         const std::string& rootUrl,
                                         const Plugins::PlayStrategy& strategy,
                                         const Plugins::TrackSelectionFilter& filter)
{
    std::vector<uint8_t> buffer;
    if (!Serialize(rootUrl, strategy, filter, buffer)) {
        MEDIA_LOGE("Failed to serialize play strategy");
        return false;
    }
    
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    if (!file) {
        MEDIA_LOGE("Failed to write play strategy to file");
        return false;
    }
    return true;
}

bool PlayStrategySerializer::ReadFromFile(std::ifstream& file,
                                          std::string& rootUrl,
                                          Plugins::PlayStrategy& strategy,
                                          Plugins::TrackSelectionFilter& filter)
{
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }
    
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
    if (buffer.empty()) {
        MEDIA_LOGE("File is empty");
        return false;
    }
    
    return Deserialize(buffer, rootUrl, strategy, filter);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS