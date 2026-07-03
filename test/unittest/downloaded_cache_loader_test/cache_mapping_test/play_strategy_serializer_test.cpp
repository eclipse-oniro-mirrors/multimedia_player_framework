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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <fstream>
#include <vector>
#include "play_strategy_serializer.h"
#include "media_source.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class PlayStrategySerializerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

Plugins::PlayStrategy CreateTestPlayStrategy()
{
    Plugins::PlayStrategy strategy;
    strategy.width = 1920;
    strategy.height = 1080;
    strategy.duration = 3600000;
    strategy.preferHDR = true;
    strategy.audioLanguage = "eng";
    strategy.subtitleLanguage = "chi";
    strategy.bufferDurationForPlaying = 5.0;
    strategy.thresholdForAutoQuickPlay = 2.5;
    return strategy;
}

Plugins::TrackSelectionFilter CreateTestTrackSelectionFilter()
{
    Plugins::TrackSelectionFilter filter;
    filter.maxVideoBitrate = 10000000;
    filter.minVideoBitrate = 500000;
    filter.maxVideoFrameRate = 60;
    filter.minVideoFrameRate = 24;
    filter.maxVideoResolution = {3840, 2160};
    filter.minVideoResolution = {640, 480};
    filter.preferredVideoMimeTypes = {"video/avc", "video/hevc"};
    filter.maxAudioBitrate = 320000;
    filter.minAudioBitrate = 48000;
    filter.maxAudioChannels = 2;
    filter.preferredAudioMimeTypes = {"audio/mp4a-latm"};
    filter.preferredAudioLanguages = {"eng", "chi", "jpn"};
    filter.preferredSubtitleLanguages = {"chi", "eng"};
    return filter;
}

HWTEST_F(PlayStrategySerializerTest, Serialize_Deserialize_Empty_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    std::vector<uint8_t> buffer;
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    EXPECT_FALSE(buffer.empty());
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserializedStrategy;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserializedStrategy, deserializedFilter);
    EXPECT_TRUE(result);
    
    EXPECT_EQ(strategy.width, deserializedStrategy.width);
    EXPECT_EQ(strategy.height, deserializedStrategy.height);
    EXPECT_EQ(strategy.duration, deserializedStrategy.duration);
    EXPECT_EQ(strategy.preferHDR, deserializedStrategy.preferHDR);
    EXPECT_EQ(strategy.audioLanguage, deserializedStrategy.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserializedStrategy.subtitleLanguage);
    EXPECT_EQ(strategy.bufferDurationForPlaying, deserializedStrategy.bufferDurationForPlaying);
    EXPECT_EQ(strategy.thresholdForAutoQuickPlay, deserializedStrategy.thresholdForAutoQuickPlay);
}

HWTEST_F(PlayStrategySerializerTest, Serialize_Deserialize_FullData_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    auto strategy = CreateTestPlayStrategy();
    auto filter = CreateTestTrackSelectionFilter();
    std::vector<uint8_t> buffer;
    
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    EXPECT_FALSE(buffer.empty());
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserializedStrategy;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserializedStrategy, deserializedFilter);
    EXPECT_TRUE(result);
    
    EXPECT_EQ(strategy.width, deserializedStrategy.width);
    EXPECT_EQ(strategy.height, deserializedStrategy.height);
    EXPECT_EQ(strategy.duration, deserializedStrategy.duration);
    EXPECT_EQ(strategy.preferHDR, deserializedStrategy.preferHDR);
    EXPECT_EQ(strategy.audioLanguage, deserializedStrategy.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserializedStrategy.subtitleLanguage);
    EXPECT_EQ(strategy.bufferDurationForPlaying, deserializedStrategy.bufferDurationForPlaying);
    EXPECT_EQ(strategy.thresholdForAutoQuickPlay, deserializedStrategy.thresholdForAutoQuickPlay);
    
    EXPECT_EQ(filter.maxVideoBitrate, deserializedFilter.maxVideoBitrate);
    EXPECT_EQ(filter.minVideoBitrate, deserializedFilter.minVideoBitrate);
    EXPECT_EQ(filter.maxVideoFrameRate, deserializedFilter.maxVideoFrameRate);
    EXPECT_EQ(filter.minVideoFrameRate, deserializedFilter.minVideoFrameRate);
    EXPECT_EQ(filter.maxVideoResolution.first, deserializedFilter.maxVideoResolution.first);
    EXPECT_EQ(filter.maxVideoResolution.second, deserializedFilter.maxVideoResolution.second);
    EXPECT_EQ(filter.minVideoResolution.first, deserializedFilter.minVideoResolution.first);
    EXPECT_EQ(filter.minVideoResolution.second, deserializedFilter.minVideoResolution.second);
    EXPECT_EQ(filter.preferredVideoMimeTypes.size(), deserializedFilter.preferredVideoMimeTypes.size());
    for (size_t i = 0; i < filter.preferredVideoMimeTypes.size(); ++i) {
        EXPECT_EQ(filter.preferredVideoMimeTypes[i], deserializedFilter.preferredVideoMimeTypes[i]);
    }
    EXPECT_EQ(filter.maxAudioBitrate, deserializedFilter.maxAudioBitrate);
    EXPECT_EQ(filter.minAudioBitrate, deserializedFilter.minAudioBitrate);
    EXPECT_EQ(filter.maxAudioChannels, deserializedFilter.maxAudioChannels);
    EXPECT_EQ(filter.preferredAudioMimeTypes.size(), deserializedFilter.preferredAudioMimeTypes.size());
    for (size_t i = 0; i < filter.preferredAudioMimeTypes.size(); ++i) {
        EXPECT_EQ(filter.preferredAudioMimeTypes[i], deserializedFilter.preferredAudioMimeTypes[i]);
    }
    EXPECT_EQ(filter.preferredAudioLanguages.size(), deserializedFilter.preferredAudioLanguages.size());
    for (size_t i = 0; i < filter.preferredAudioLanguages.size(); ++i) {
        EXPECT_EQ(filter.preferredAudioLanguages[i], deserializedFilter.preferredAudioLanguages[i]);
    }
    EXPECT_EQ(filter.preferredSubtitleLanguages.size(), deserializedFilter.preferredSubtitleLanguages.size());
    for (size_t i = 0; i < filter.preferredSubtitleLanguages.size(); ++i) {
        EXPECT_EQ(filter.preferredSubtitleLanguages[i], deserializedFilter.preferredSubtitleLanguages[i]);
    }
}

HWTEST_F(PlayStrategySerializerTest, Serialize_PreferHdr_True_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    strategy.preferHDR = true;
    Plugins::TrackSelectionFilter filter;
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserialized;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserialized, filter);
    EXPECT_TRUE(result);
    EXPECT_TRUE(deserialized.preferHDR);
}

HWTEST_F(PlayStrategySerializerTest, Serialize_PreferHdr_False_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    strategy.preferHDR = false;
    Plugins::TrackSelectionFilter filter;
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserialized;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserialized, filter);
    EXPECT_TRUE(result);
    EXPECT_FALSE(deserialized.preferHDR);
}

HWTEST_F(PlayStrategySerializerTest, Serialize_EmptyStrings_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy;
    strategy.width = 1280;
    strategy.height = 720;
    strategy.duration = 0;
    strategy.preferHDR = false;
    strategy.audioLanguage = "";
    strategy.subtitleLanguage = "";
    strategy.bufferDurationForPlaying = 0.0;
    strategy.thresholdForAutoQuickPlay = 0.0;
    Plugins::TrackSelectionFilter filter;
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserialized;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserialized, filter);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategy.audioLanguage, deserialized.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserialized.subtitleLanguage);
}

HWTEST_F(PlayStrategySerializerTest, Serialize_UnicodeStrings_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    strategy.audioLanguage = "\xe4\xb8\xad\xe6\x96\x87";
    strategy.subtitleLanguage = "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e";
    Plugins::TrackSelectionFilter filter;
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserialized;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserialized, filter);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategy.audioLanguage, deserialized.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserialized.subtitleLanguage);
}

HWTEST_F(PlayStrategySerializerTest, Serialize_EmptyFilterVectors_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    Plugins::TrackSelectionFilter filter;
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, strategy, deserializedFilter);
    EXPECT_TRUE(result);
    EXPECT_TRUE(deserializedFilter.preferredVideoMimeTypes.empty());
    EXPECT_TRUE(deserializedFilter.preferredAudioMimeTypes.empty());
    EXPECT_TRUE(deserializedFilter.preferredAudioLanguages.empty());
    EXPECT_TRUE(deserializedFilter.preferredSubtitleLanguages.empty());
}

HWTEST_F(PlayStrategySerializerTest, Serialize_FilterWithEmptyStrings_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    Plugins::TrackSelectionFilter filter;
    filter.preferredVideoMimeTypes = {""};
    filter.preferredAudioMimeTypes = {""};
    filter.preferredAudioLanguages = {""};
    filter.preferredSubtitleLanguages = {""};
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, strategy, deserializedFilter);
    EXPECT_TRUE(result);
    EXPECT_EQ(filter.preferredVideoMimeTypes.size(), deserializedFilter.preferredVideoMimeTypes.size());
    EXPECT_EQ(filter.preferredAudioMimeTypes.size(), deserializedFilter.preferredAudioMimeTypes.size());
    EXPECT_EQ(filter.preferredAudioLanguages.size(), deserializedFilter.preferredAudioLanguages.size());
    EXPECT_EQ(filter.preferredSubtitleLanguages.size(), deserializedFilter.preferredSubtitleLanguages.size());
}

HWTEST_F(PlayStrategySerializerTest, Deserialize_EmptyBuffer_001, TestSize.Level0)
{
    std::vector<uint8_t> buffer;
    std::string rootUrl;
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    
    bool result = PlayStrategySerializer::Deserialize(buffer, rootUrl, strategy, filter);
    EXPECT_FALSE(result);
}

HWTEST_F(PlayStrategySerializerTest, WriteToFile_FileNotOpen_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    std::ofstream file;
    auto strategy = CreateTestPlayStrategy();
    auto filter = CreateTestTrackSelectionFilter();
    
    bool result = PlayStrategySerializer::WriteToFile(file, rootUrl, strategy, filter);
    EXPECT_FALSE(result);
}

HWTEST_F(PlayStrategySerializerTest, ReadFromFile_FileNotOpen_001, TestSize.Level0)
{
    std::ifstream file;
    std::string rootUrl;
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    
    bool result = PlayStrategySerializer::ReadFromFile(file, rootUrl, strategy, filter);
    EXPECT_FALSE(result);
}

HWTEST_F(PlayStrategySerializerTest, ReadFromFile_FileNotExist_001, TestSize.Level0)
{
    std::ifstream file("/tmp/non_existent_file_12345.bin");
    std::string rootUrl;
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    
    bool result = PlayStrategySerializer::ReadFromFile(file, rootUrl, strategy, filter);
    EXPECT_FALSE(result);
}

HWTEST_F(PlayStrategySerializerTest, RoundTrip_LargeData_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy;
    strategy.width = 7680;
    strategy.height = 4320;
    strategy.duration = 72000000;
    strategy.preferHDR = true;
    strategy.audioLanguage = "This is a very long audio language specification string for testing";
    strategy.subtitleLanguage = "This is a very long subtitle language specification string for testing purposes";
    strategy.bufferDurationForPlaying = 123.456;
    strategy.thresholdForAutoQuickPlay = 789.012;
    
    Plugins::TrackSelectionFilter filter;
    filter.maxVideoBitrate = 50000000;
    filter.minVideoBitrate = 100000;
    filter.maxVideoFrameRate = 120;
    filter.minVideoFrameRate = 1;
    filter.maxVideoResolution = {7680, 4320};
    filter.minVideoResolution = {176, 144};
    filter.preferredVideoMimeTypes = {"video/avc", "video/hevc", "video/vp9", "video/av01"};
    for (int i = 0; i < 100; ++i) {
        filter.preferredVideoMimeTypes.push_back("video/test" + std::to_string(i));
    }
    filter.maxAudioBitrate = 512000;
    filter.minAudioBitrate = 8000;
    filter.maxAudioChannels = 8;
    filter.preferredAudioMimeTypes = {"audio/mp4a-latm", "audio/ac3", "audio/eac3"};
    for (int i = 0; i < 50; ++i) {
        filter.preferredAudioLanguages.push_back("lang" + std::to_string(i));
    }
    filter.preferredSubtitleLanguages = {"chi", "eng", "jpn", "kor"};
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    EXPECT_FALSE(buffer.empty());
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserializedStrategy;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserializedStrategy, deserializedFilter);
    EXPECT_TRUE(result);
    
    EXPECT_EQ(strategy.width, deserializedStrategy.width);
    EXPECT_EQ(strategy.height, deserializedStrategy.height);
    EXPECT_EQ(strategy.duration, deserializedStrategy.duration);
    EXPECT_EQ(strategy.preferHDR, deserializedStrategy.preferHDR);
    EXPECT_EQ(strategy.audioLanguage, deserializedStrategy.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserializedStrategy.subtitleLanguage);
    EXPECT_EQ(strategy.bufferDurationForPlaying, deserializedStrategy.bufferDurationForPlaying);
    EXPECT_EQ(strategy.thresholdForAutoQuickPlay, deserializedStrategy.thresholdForAutoQuickPlay);
    
    EXPECT_EQ(filter.preferredVideoMimeTypes.size(), deserializedFilter.preferredVideoMimeTypes.size());
    EXPECT_EQ(filter.preferredAudioLanguages.size(), deserializedFilter.preferredAudioLanguages.size());
}

HWTEST_F(PlayStrategySerializerTest, RoundTrip_SpecialCharacters_001, TestSize.Level0)
{
    std::string rootUrl = "http://example.com";
    Plugins::PlayStrategy strategy = CreateTestPlayStrategy();
    strategy.audioLanguage = "en-US";
    strategy.subtitleLanguage = "zh-CN@test";
    
    Plugins::TrackSelectionFilter filter;
    filter.preferredVideoMimeTypes = {"video/avc", "video/hevc"};
    filter.preferredAudioLanguages = {"en-US", "zh-CN", "ja-JP"};
    filter.preferredSubtitleLanguages = {"zh-CN@test", "en-US#123"};
    
    std::vector<uint8_t> buffer;
    bool result = PlayStrategySerializer::Serialize(rootUrl, strategy, filter, buffer);
    EXPECT_TRUE(result);
    
    std::string deserializedRootUrl;
    Plugins::PlayStrategy deserializedStrategy;
    Plugins::TrackSelectionFilter deserializedFilter;
    result = PlayStrategySerializer::Deserialize(buffer, deserializedRootUrl, deserializedStrategy, deserializedFilter);
    EXPECT_TRUE(result);
    
    EXPECT_EQ(strategy.audioLanguage, deserializedStrategy.audioLanguage);
    EXPECT_EQ(strategy.subtitleLanguage, deserializedStrategy.subtitleLanguage);
    EXPECT_EQ(filter.preferredVideoMimeTypes.size(), deserializedFilter.preferredVideoMimeTypes.size());
    EXPECT_EQ(filter.preferredAudioLanguages.size(), deserializedFilter.preferredAudioLanguages.size());
    EXPECT_EQ(filter.preferredSubtitleLanguages.size(), deserializedFilter.preferredSubtitleLanguages.size());
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS