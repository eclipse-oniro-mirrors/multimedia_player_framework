/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <future>
#include <tuple>
#include "dfx_agent_test.h"
#include "player.h"
#include "media_demuxer.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
namespace {
// Callback registration and event dispatch share the DFX task queue. Waiting on
// the result verifies dispatch without sleeps; shared ownership also covers timeout.
AVMetricsEvent CaptureMetrics(const std::shared_ptr<DfxAgent>& agent, const DfxEvent& event)
{
    auto result = std::make_shared<std::promise<AVMetricsEvent>>();
    auto future = result->get_future();
    agent->SetMetricsCallback([result](std::weak_ptr<DfxAgent>, const DfxEvent& reported) {
        result->set_value(AnyCast<AVMetricsEvent>(reported.param));
    });
    agent->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::seconds(2));
    EXPECT_EQ(status, std::future_status::ready);
    return status == std::future_status::ready ? future.get() : AVMetricsEvent{};
}
}

/**
 * @tc.name  : LoadingBitratePayload
 * @tc.number: DfxAgent_LoadingBitratePayload_001
 * @tc.desc  : Preserve unsigned bitrates above INT32_MAX as int64 metrics fields.
 */
HWTEST_F(DfxAgentUnitTest, LoadingBitratePayload, TestSize.Level0)
{
    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_LOADING_BITRATE;
    event.param = std::make_pair(uint32_t{4000000000U}, uint32_t{128000});
    auto result = CaptureMetrics(agent_, event);
    EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_LOADINGRATE_CHANGE);
    ASSERT_EQ(result.details.size(), 2U);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("bitrate_before")), 4000000000LL);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("bitrate_after")), 128000);
    EXPECT_EQ(result.playbackPosition, 0);
}

/**
 * @tc.name  : LoadingErrorStages
 * @tc.number: DfxAgent_LoadingErrorStages_001
 * @tc.desc  : Map each request stage and preserve error codes and event timestamps.
 */
HWTEST_F(DfxAgentUnitTest, LoadingErrorStages, TestSize.Level0)
{
    const std::vector<std::string> stages = {"CONNECTION", "PLAYLIST", "MEDIA_DATA", "UNKNOWN"};
    for (size_t stage = 0; stage < stages.size(); ++stage) {
        SCOPED_TRACE(stage);
        DfxEvent event;
        event.type = DfxEventType::DFX_EVENT_LOADING_ERROR;
        event.param = std::make_tuple(static_cast<int32_t>(stage), int64_t{1000}, int32_t{-101});
        auto result = CaptureMetrics(agent_, event);
        EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_LOADING_ERROR);
        ASSERT_EQ(result.details.size(), 3U);
        EXPECT_EQ(AnyCast<std::string>(result.details.at("request_stage")), stages[stage]);
        EXPECT_EQ(AnyCast<int64_t>(result.details.at("error_code")), -101);
        // Each conversion samples the system/steady clock offset independently.
        auto requestTime = AnyCast<int64_t>(result.details.at("request_timestamp"));
        EXPECT_GE(requestTime, result.timeStamp - 10);
        EXPECT_LE(requestTime, result.timeStamp + 10);
    }
}

/**
 * @tc.name  : PtsDiscontinuityPayload
 * @tc.number: DfxAgent_PtsDiscontinuityPayload_001
 * @tc.desc  : Report the discontinuous PTS values without unrelated audio parameters.
 */
HWTEST_F(DfxAgentUnitTest, PtsDiscontinuityPayload, TestSize.Level0)
{
    MediaDiscontinueInfo info{};
    info.streamType = 2;
    info.discontinueType = 2;
    info.ptsBefore = 9000000;
    info.ptsAfter = 1000000;
    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_MEDIA_DISCONTINUE;
    event.param = info;
    auto result = CaptureMetrics(agent_, event);
    EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY);
    ASSERT_EQ(result.details.size(), 4U);
    EXPECT_EQ(AnyCast<std::string>(result.details.at("media_stream_type")), "VIDEO");
    EXPECT_EQ(AnyCast<std::string>(result.details.at("discontinue_type")), "PTS");
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("pts_before")), info.ptsBefore);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("pts_after")), info.ptsAfter);
}

/**
 * @tc.name  : AudioDiscontinuityPayload
 * @tc.number: DfxAgent_AudioDiscontinuityPayload_001
 * @tc.desc  : Preserve all before/after audio format fields and omit PTS fields.
 */
HWTEST_F(DfxAgentUnitTest, AudioDiscontinuityPayload, TestSize.Level0)
{
    MediaDiscontinueInfo info{};
    info.streamType = 1;
    info.discontinueType = 1;
    info.sampleRateBefore = 44100;
    info.sampleRateAfter = 48000;
    info.channelsBefore = 1;
    info.channelsAfter = 2;
    info.sampleFormatBefore = 1;
    info.sampleFormatAfter = 3;
    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_MEDIA_DISCONTINUE;
    event.param = info;
    auto result = CaptureMetrics(agent_, event);
    EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY);
    ASSERT_EQ(result.details.size(), 8U);
    EXPECT_EQ(AnyCast<std::string>(result.details.at("media_stream_type")), "AUDIO");
    EXPECT_EQ(AnyCast<std::string>(result.details.at("discontinue_type")), "AUDIO_PARAM");
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("sample_rate_before")), 44100);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("sample_rate_after")), 48000);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("channels_before")), 1);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("channels_after")), 2);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("sample_format_before")), 1);
    EXPECT_EQ(AnyCast<int64_t>(result.details.at("sample_format_after")), 3);
}

/**
 * @tc.name  : AudioStatusPayload
 * @tc.number: DfxAgent_AudioStatusPayload_001
 * @tc.desc  : Convert renderer states and preserve the interruption hint.
 */
HWTEST_F(DfxAgentUnitTest, AudioStatusPayload, TestSize.Level0)
{
    const std::vector<int32_t> states = {2, 3, 5, -1};
    const std::vector<std::string> names = {"RUNNING", "STOPPED", "PAUSED", "UNKNOWN"};
    for (size_t index = 0; index < states.size(); ++index) {
        SCOPED_TRACE(index);
        DfxEvent event;
        event.type = DfxEventType::DFX_EVENT_AUDIO_STATUS;
        event.param = AudioStatusInfo{states[index], states[(index + 1) % states.size()], 4};
        auto result = CaptureMetrics(agent_, event);
        EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_AUDIO_ABNORMAL);
        ASSERT_EQ(result.details.size(), 3U);
        EXPECT_EQ(AnyCast<std::string>(result.details.at("state_before")), names[index]);
        EXPECT_EQ(AnyCast<std::string>(result.details.at("state_after")), names[(index + 1) % names.size()]);
        EXPECT_EQ(AnyCast<int32_t>(result.details.at("interrupt_hint")), 4);
    }
}

/**
 * @tc.name  : CodecAbnormalPayload
 * @tc.number: DfxAgent_CodecAbnormalPayload_001
 * @tc.desc  : Distinguish audio/video/unknown decoders and retain signed error codes.
 */
HWTEST_F(DfxAgentUnitTest, CodecAbnormalPayload, TestSize.Level0)
{
    const std::vector<std::string> decoders = {"UNKNOWN", "VIDEO", "AUDIO"};
    for (size_t index = 0; index < decoders.size(); ++index) {
        SCOPED_TRACE(index);
        DfxEvent event;
        event.type = DfxEventType::DFX_EVENT_CODEC_ABNORMAL;
        event.param = CodecAbnormalInfo{static_cast<int32_t>(index), -1001};
        auto result = CaptureMetrics(agent_, event);
        EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_CODEC_ABNORMAL);
        ASSERT_EQ(result.details.size(), 2U);
        EXPECT_EQ(AnyCast<std::string>(result.details.at("decoder_type")), decoders[index]);
        EXPECT_EQ(AnyCast<int64_t>(result.details.at("error_code")), -1001);
    }
}

/**
 * @tc.name  : LipAsyncPayload
 * @tc.number: DfxAgent_LipAsyncPayload_001
 * @tc.desc  : Map desync direction and use its end time as the playback position.
 */
HWTEST_F(DfxAgentUnitTest, LipAsyncPayload, TestSize.Level0)
{
    const std::vector<std::string> directions = {"UNKNOWN", "VIDEO_AHEAD", "VIDEO_BEHIND"};
    for (size_t index = 0; index < directions.size(); ++index) {
        SCOPED_TRACE(index);
        DfxEvent event;
        event.type = DfxEventType::DFX_EVENT_AVDESYNC;
        event.param = LipAsyncInfo{static_cast<int32_t>(index), 1000, 2500};
        auto result = CaptureMetrics(agent_, event);
        EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_LIP_ASYNC);
        EXPECT_EQ(result.playbackPosition, 2500);
        ASSERT_EQ(result.details.size(), 3U);
        EXPECT_EQ(AnyCast<std::string>(result.details.at("async_type")), directions[index]);
        EXPECT_EQ(AnyCast<int64_t>(result.details.at("start_time")), 1000);
        EXPECT_EQ(AnyCast<int64_t>(result.details.at("end_time")), 2500);
    }
}
/**
 * @tc.name  : NetworkMediaChangePayload
 * @tc.number: DfxAgent_NetworkMediaChangePayload_001
 * @tc.desc  : Preserve network stream, resolution, audio and codec changes in the metrics callback.
 */
HWTEST_F(DfxAgentUnitTest, NetworkMediaChangePayload, TestSize.Level0)
{
    MediaChangeInfo info{};
    info.streamType = 1;
    info.changeReason = 1;
    info.streamIdBefore = 2;
    info.streamIdAfter = 3;
    info.bitrateBefore = 128000;
    info.bitrateAfter = 256000;
    info.videoWidthBefore = 1280;
    info.videoHeightBefore = 720;
    info.videoWidthAfter = 1920;
    info.videoHeightAfter = 1080;
    info.videoFrameRateBefore = 25;
    info.videoFrameRateAfter = 30;
    info.audioChannelsBefore = 1;
    info.audioChannelsAfter = 2;
    info.audioSampleRateBefore = 44100;
    info.audioSampleRateAfter = 48000;
    info.videoTypeBefore = 0;
    info.videoTypeAfter = 2;
    info.codecsBefore = "avc1";
    info.codecsAfter = "hvc1";
    info.originCodecsBefore = "avc1.64001f";
    info.originCodecsAfter = "hvc1.1.6.L93";
    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_MEDIA_CHANGED;
    event.param = info;
    auto result = CaptureMetrics(agent_, event);
    EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_CHANGED);
    ASSERT_EQ(result.details.size(), 32U);
    EXPECT_FALSE(AnyCast<bool>(result.details.at("is_local_fd")));
    const std::map<std::string, int64_t> expectedNumbers = {
        {"stream_id_before", 2}, {"stream_id_after", 3},
        {"bitrate_before", 128000}, {"bitrate_after", 256000},
        {"video_width_before", 1280}, {"video_height_before", 720},
        {"video_width_after", 1920}, {"video_height_after", 1080},
        {"video_framerate_before", 25}, {"video_framerate_after", 30},
        {"audio_channels_before", 1}, {"audio_channels_after", 2},
        {"audio_sample_rate_before", 44100}, {"audio_sample_rate_after", 48000}};
    for (const auto& field : expectedNumbers) {
        SCOPED_TRACE(field.first);
        EXPECT_EQ(AnyCast<int64_t>(result.details.at(field.first)), field.second);
    }
    const std::map<std::string, std::string> expectedStrings = {
        {"media_stream_type", "VIDEO"}, {"change_reason", "NETWORK_QUALITY"}, {"change_result", "SUCCESS"},
        {"video_type_before", "SDR"}, {"video_type_after", "HDR_10"},
        {"codecs_before", info.codecsBefore}, {"codecs_after", info.codecsAfter},
        {"origin_codecs_before", info.originCodecsBefore}, {"origin_codecs_after", info.originCodecsAfter}};
    for (const auto& field : expectedStrings) {
        SCOPED_TRACE(field.first);
        EXPECT_EQ(AnyCast<std::string>(result.details.at(field.first)), field.second);
    }
}

/**
 * @tc.name  : LocalMediaChangeOmitsNetworkFields
 * @tc.number: DfxAgent_LocalMediaChangeOmitsNetworkFields_001
 * @tc.desc  : Local track changes retain languages and MIME types but exclude network-only fields.
 */
HWTEST_F(DfxAgentUnitTest, LocalMediaChangeOmitsNetworkFields, TestSize.Level0)
{
    MediaChangeInfo info{};
    info.isLocalFd = true;
    info.changeReason = 2;
    info.changeResult = -1;
    info.audioLangBefore = "en";
    info.audioLangAfter = "zh";
    info.subtitleLangBefore = "zh";
    info.subtitleLangAfter = "en";
    info.audioMimeTypeBefore = "audio/aac";
    info.audioMimeTypeAfter = "audio/flac";
    info.videoMimeTypeBefore = "video/avc";
    info.videoMimeTypeAfter = "video/hevc";
    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_MEDIA_CHANGED;
    event.param = info;
    auto result = CaptureMetrics(agent_, event);
    EXPECT_EQ(result.metricsEventType, AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_CHANGED);
    ASSERT_EQ(result.details.size(), 25U);
    EXPECT_TRUE(AnyCast<bool>(result.details.at("is_local_fd")));
    EXPECT_EQ(AnyCast<std::string>(result.details.at("change_reason")), "MANUAL");
    EXPECT_EQ(AnyCast<std::string>(result.details.at("change_result")), "FAILED");
    const std::map<std::string, std::string> expectedStrings = {
        {"audio_lang_before", "en"}, {"audio_lang_after", "zh"},
        {"subtitle_lang_before", "zh"}, {"subtitle_lang_after", "en"},
        {"audio_mime_type_before", "audio/aac"}, {"audio_mime_type_after", "audio/flac"},
        {"video_mime_type_before", "video/avc"}, {"video_mime_type_after", "video/hevc"}};
    for (const auto& field : expectedStrings) {
        SCOPED_TRACE(field.first);
        EXPECT_EQ(AnyCast<std::string>(result.details.at(field.first)), field.second);
    }
    for (const auto& key : {"media_stream_type", "bitrate_before", "bitrate_after", "codecs_before",
        "codecs_after", "origin_codecs_before", "origin_codecs_after"}) {
        EXPECT_EQ(result.details.count(key), 0U) << key;
    }
}
} // namespace Media
} // namespace OHOS
