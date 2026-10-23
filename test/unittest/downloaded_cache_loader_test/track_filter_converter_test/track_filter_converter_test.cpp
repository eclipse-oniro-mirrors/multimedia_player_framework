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
#include <string>
#include <utility>
#include "track_filter_converter.h"
#include "player.h"
#include "media_source.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static AVPlayTrackSelectionFilter CreateFullAVPlayFilter()
{
    AVPlayTrackSelectionFilter f;
    f.maxVideoBitrate = 10000000;
    f.minVideoBitrate = 500000;
    f.maxVideoFrameRate = 60;
    f.minVideoFrameRate = 24;
    f.maxVideoResolution = {3840, 2160};
    f.minVideoResolution = {640, 480};
    f.preferredVideoMimeTypes = {"video/avc", "video/hevc"};
    f.maxAudioBitrate = 320000;
    f.minAudioBitrate = 48000;
    f.maxAudioChannels = 2;
    f.preferredAudioMimeTypes = {"audio/mp4a-latm"};
    f.preferredAudioLanguages = {"eng", "chi", "jpn"};
    f.preferredSubtitleLanguages = {"chi", "eng"};
    return f;
}

static Plugins::TrackSelectionFilter CreateFullPluginsFilter()
{
    Plugins::TrackSelectionFilter f;
    f.maxVideoBitrate = 10000000;
    f.minVideoBitrate = 500000;
    f.maxVideoFrameRate = 60;
    f.minVideoFrameRate = 24;
    f.maxVideoResolution = {3840, 2160};
    f.minVideoResolution = {640, 480};
    f.preferredVideoMimeTypes = {"video/avc", "video/hevc"};
    f.maxAudioBitrate = 320000;
    f.minAudioBitrate = 48000;
    f.maxAudioChannels = 2;
    f.preferredAudioMimeTypes = {"audio/mp4a-latm"};
    f.preferredAudioLanguages = {"eng", "chi", "jpn"};
    f.preferredSubtitleLanguages = {"chi", "eng"};
    return f;
}

class TrackFilterConverterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(TrackFilterConverterTest, ToPlugins_FullFilter_AllFieldsPreserved, TestSize.Level0)
{
    auto avFilter = CreateFullAVPlayFilter();
    auto pluginFilter = TrackFilterConverter::ToPlugins(avFilter);

    EXPECT_EQ(pluginFilter.maxVideoBitrate, avFilter.maxVideoBitrate);
    EXPECT_EQ(pluginFilter.minVideoBitrate, avFilter.minVideoBitrate);
    EXPECT_EQ(pluginFilter.maxVideoFrameRate, avFilter.maxVideoFrameRate);
    EXPECT_EQ(pluginFilter.minVideoFrameRate, avFilter.minVideoFrameRate);
    EXPECT_EQ(pluginFilter.maxVideoResolution.first, avFilter.maxVideoResolution.first);
    EXPECT_EQ(pluginFilter.maxVideoResolution.second, avFilter.maxVideoResolution.second);
    EXPECT_EQ(pluginFilter.minVideoResolution.first, avFilter.minVideoResolution.first);
    EXPECT_EQ(pluginFilter.minVideoResolution.second, avFilter.minVideoResolution.second);
    EXPECT_EQ(pluginFilter.preferredVideoMimeTypes, avFilter.preferredVideoMimeTypes);
    EXPECT_EQ(pluginFilter.maxAudioBitrate, avFilter.maxAudioBitrate);
    EXPECT_EQ(pluginFilter.minAudioBitrate, avFilter.minAudioBitrate);
    EXPECT_EQ(pluginFilter.maxAudioChannels, avFilter.maxAudioChannels);
    EXPECT_EQ(pluginFilter.preferredAudioMimeTypes, avFilter.preferredAudioMimeTypes);
    EXPECT_EQ(pluginFilter.preferredAudioLanguages, avFilter.preferredAudioLanguages);
    EXPECT_EQ(pluginFilter.preferredSubtitleLanguages, avFilter.preferredSubtitleLanguages);
}

HWTEST_F(TrackFilterConverterTest, ToAVPlay_FullFilter_AllFieldsPreserved, TestSize.Level0)
{
    auto pluginFilter = CreateFullPluginsFilter();
    auto avFilter = TrackFilterConverter::ToAVPlay(pluginFilter);

    EXPECT_EQ(avFilter.maxVideoBitrate, pluginFilter.maxVideoBitrate);
    EXPECT_EQ(avFilter.minVideoBitrate, pluginFilter.minVideoBitrate);
    EXPECT_EQ(avFilter.maxVideoFrameRate, pluginFilter.maxVideoFrameRate);
    EXPECT_EQ(avFilter.minVideoFrameRate, pluginFilter.minVideoFrameRate);
    EXPECT_EQ(avFilter.maxVideoResolution.first, pluginFilter.maxVideoResolution.first);
    EXPECT_EQ(avFilter.maxVideoResolution.second, pluginFilter.maxVideoResolution.second);
    EXPECT_EQ(avFilter.minVideoResolution.first, pluginFilter.minVideoResolution.first);
    EXPECT_EQ(avFilter.minVideoResolution.second, pluginFilter.minVideoResolution.second);
    EXPECT_EQ(avFilter.preferredVideoMimeTypes, pluginFilter.preferredVideoMimeTypes);
    EXPECT_EQ(avFilter.maxAudioBitrate, pluginFilter.maxAudioBitrate);
    EXPECT_EQ(avFilter.minAudioBitrate, pluginFilter.minAudioBitrate);
    EXPECT_EQ(avFilter.maxAudioChannels, pluginFilter.maxAudioChannels);
    EXPECT_EQ(avFilter.preferredAudioMimeTypes, pluginFilter.preferredAudioMimeTypes);
    EXPECT_EQ(avFilter.preferredAudioLanguages, pluginFilter.preferredAudioLanguages);
    EXPECT_EQ(avFilter.preferredSubtitleLanguages, pluginFilter.preferredSubtitleLanguages);
}

HWTEST_F(TrackFilterConverterTest, RoundTrip_AllDefault_Preserved, TestSize.Level0)
{
    AVPlayTrackSelectionFilter avDefault;
    auto pluginResult = TrackFilterConverter::ToPlugins(avDefault);
    auto avResult = TrackFilterConverter::ToAVPlay(pluginResult);

    EXPECT_EQ(avResult.maxVideoBitrate, -1);
    EXPECT_EQ(avResult.minVideoBitrate, -1);
    EXPECT_EQ(avResult.maxVideoFrameRate, -1);
    EXPECT_EQ(avResult.minVideoFrameRate, -1);
    EXPECT_EQ(avResult.maxVideoResolution.first, -1);
    EXPECT_EQ(avResult.maxVideoResolution.second, -1);
    EXPECT_EQ(avResult.minVideoResolution.first, -1);
    EXPECT_EQ(avResult.minVideoResolution.second, -1);
    EXPECT_TRUE(avResult.preferredVideoMimeTypes.empty());
    EXPECT_EQ(avResult.maxAudioBitrate, -1);
    EXPECT_EQ(avResult.minAudioBitrate, -1);
    EXPECT_EQ(avResult.maxAudioChannels, -1);
    EXPECT_TRUE(avResult.preferredAudioMimeTypes.empty());
    EXPECT_TRUE(avResult.preferredAudioLanguages.empty());
    EXPECT_TRUE(avResult.preferredSubtitleLanguages.empty());
}

HWTEST_F(TrackFilterConverterTest, RoundTrip_PartialFilter_Preserved, TestSize.Level1)
{
    AVPlayTrackSelectionFilter avPartial;
    avPartial.maxVideoBitrate = 5000000;
    avPartial.preferredAudioLanguages = {"eng"};
    avPartial.preferredSubtitleLanguages = {"chi"};

    auto pluginResult = TrackFilterConverter::ToPlugins(avPartial);
    auto avResult = TrackFilterConverter::ToAVPlay(pluginResult);

    EXPECT_EQ(avResult.maxVideoBitrate, 5000000);
    EXPECT_EQ(avResult.minVideoBitrate, -1);
    EXPECT_EQ(avResult.maxVideoFrameRate, -1);
    EXPECT_TRUE(avResult.preferredVideoMimeTypes.empty());
    EXPECT_EQ(avResult.preferredAudioLanguages.size(), 1);
    EXPECT_EQ(avResult.preferredAudioLanguages[0], "eng");
    EXPECT_EQ(avResult.preferredSubtitleLanguages.size(), 1);
    EXPECT_EQ(avResult.preferredSubtitleLanguages[0], "chi");
}

} // namespace Media
} // namespace OHOS
