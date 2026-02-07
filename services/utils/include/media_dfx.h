/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef MEDIA_DFX_H
#define MEDIA_DFX_H

#include <cstring>
#include <list>
#include <memory>
#include <map>
#include <vector>
#include <string>
#include <refbase.h>
#include "nocopyable.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
#include "meta/meta.h"
#include "meta/format.h"
#ifndef CROSS_PLATFORM
#include "nlohmann/json.hpp"
#endif
#include <chrono>
#include <mutex>

namespace OHOS {
namespace Media {
#ifndef CROSS_PLATFORM
using json = nlohmann::json;
#endif

struct StallingInfo {
    std::string appName {};
    int64_t lagDuration {0};
    uint8_t sourceType {0};
    uint64_t instanceId {0};
    int64_t timeStamp {0};
    int64_t playbackPosition {0};
    std::string stage {};
    std::vector<int64_t> stallingInfo {};
};

struct PlaybackEventInfo {
    uint32_t prepareDuration {0};
    uint32_t playTotalDuration {0};
    int64_t timeStamp {0};
    uint32_t firstDownloadTime {0};
    uint32_t firstFrameDecapsulationTime {0};
    uint32_t loadingCount {0};
    uint32_t totalLoadingTime {0};
    int64_t totalDownLoadBytes {0};
    uint32_t stallingCount {0};
    uint32_t totalStallingTime {0};
};

using StallingEventList = std::list<std::pair<uint64_t, std::shared_ptr<std::vector<StallingInfo>>>>;

enum CallType {
    AVPLAYER,
    AVRECORDER,
    METADATA_RETRIEVER,
    IMAGE_GENERATER,
    AVDEMUXER,
    AVMUXER,
    VIDEO_DECODER,
    VIDEO_ENCODER,
    AUDIO_DECODER,
    AUDIO_ENCODER,
    SOUNDPOOL,
    SCREEN_CAPTRUER,
    AVTRANSCODER
};
class __attribute__((visibility("default"))) MediaEvent : public NoCopyable {
public:
    MediaEvent() = default;
    ~MediaEvent() = default;
    bool CreateMsg(const char *format, ...) __attribute__((__format__(printf, 2, 3)));
    void EventWrite(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        std::string module);
    void EventWriteWithAppInfo(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        std::string module, std::string status, int32_t appUid, int32_t appPid);
    void EventWriteBundleName(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        std::string module, std::string status, int32_t appUid, int32_t appPid, std::string bundleName);
    void PlayerLagStallingEventWrite(const std::string& appName, const std::string& instanceId,
        uint8_t sourceType, int32_t lagDuration, const std::string& msg);
    void SourceEventWrite(const std::string& eventName, OHOS::HiviewDFX::HiSysEvent::EventType type, const std::string&
        appName, uint64_t instanceId, const std::string& callerType, int8_t sourceType, const std::string& sourceUrl,
        const std::string& errMsg);
    void ScreenCaptureEventWrite(const std::string& eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::string& appName, uint64_t instanceId, int8_t captureMode, int8_t dataMode, int32_t errorCode,
        const std::string& errMsg);
    void CommonStatisicsEventWrite(CallType callType, OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<Meta>>>>& infoMap);
    void PlaybackStatisticsEventWrite(CallType callType, OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<std::vector<OHOS::Media::Format>>>>>
            &infoMap);
    void MediaKitStatistics(const std::string& syscap, const std::string& appName, const std::string& instanceId,
        const std::string& APICall, const std::string& events);
private:
    void StatisicsHiSysEventWrite(CallType callType, OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::vector<std::string>& infoArr);
#ifndef CROSS_PLATFORM
    void ParseOneEvent(const std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>> &listPair, json& metaInfoJson);
#endif
    std::string msg_;
};


__attribute__((visibility("default"))) void BehaviorEventWrite(std::string status, std::string module);
__attribute__((visibility("default"))) void BehaviorEventWriteForScreenCapture(std::string status,
    std::string module, int32_t appUid, int32_t appPid);
__attribute__((visibility("default"))) void StatisticEventWriteBundleName(std::string status,
    std::string module, std::string bundleName = "");
__attribute__((visibility("default"))) void FaultEventWrite(std::string msg, std::string module);
__attribute__((visibility("default"))) void FaultSourceEventWrite(const std::string& appName, uint64_t instanceId,
    const std::string& callerType, int8_t sourceType, const std::string& sourceUrl, const std::string& errorMessage);
__attribute__((visibility("default"))) void FaultScreenCaptureEventWrite(const std::string& appName,
    uint64_t instanceId, int8_t captureMode, int8_t dataMode, int32_t errorCode, const std::string& errorMessage);
__attribute__((visibility("default"))) int32_t CreateMediaInfo(CallType callType, int32_t uid, uint64_t instanceId);
__attribute__((visibility("default"))) int32_t AppendMediaInfo(const std::shared_ptr<Meta>& meta, uint64_t instanceId);
__attribute__((visibility("default"))) int32_t ReportMediaInfo(uint64_t instanceId);
__attribute__((visibility("default"))) void ReportTranscoderMediaInfo(int32_t uid, uint64_t instanceId,
    std::vector<std::pair<std::string, std::string>> mediaInfo, int32_t errCode);
__attribute__((visibility("default"))) uint64_t GetMediaInfoContainInstanceNum();
__attribute__((visibility("default"))) void GetMaxInstanceNumber(CallType callType, int32_t uid,
    uint64_t instanceId, int32_t curInsNumber);
__attribute__((visibility("default"))) void UpdateMaxInsNumberMap(CallType callType);
__attribute__((visibility("default"))) bool GetPlaybackEventInfo(const OHOS::Media::Format& fmt,
    PlaybackEventInfo& playbackEventInfo);
__attribute__((visibility("default"))) int32_t CreateStallingInfo(CallType callType, int32_t uid,
    uint64_t instanceId);
__attribute__((visibility("default"))) int32_t CreatePlaybackInfo(CallType callType, int32_t uid, uint64_t instanceId);

__attribute__((visibility("default"))) int32_t AppendStallingInfo(const StallingInfo &info, uint64_t instanceId);
__attribute__((visibility("default"))) int32_t AppendPlaybackInfo(
    const std::shared_ptr<OHOS::Media::Format> &fmt, uint64_t instanceId);

class __attribute__((visibility("default"))) MediaTrace : public NoCopyable {
public:
    explicit MediaTrace(const std::string &funcName, HiTraceOutputLevel level = HITRACE_LEVEL_INFO,
        const std::string &customArgs = "");
    static void TraceBegin(const std::string &funcName, int32_t taskId, HiTraceOutputLevel level = HITRACE_LEVEL_INFO,
        const std::string &customCategory = "", const std::string &customArgs = "");
    static void TraceEnd(const std::string &funcName, int32_t taskId, HiTraceOutputLevel level = HITRACE_LEVEL_INFO);
    static void CounterTrace(const std::string &varName, int32_t val, HiTraceOutputLevel level = HITRACE_LEVEL_INFO);
    ~MediaTrace();
private:
    HiTraceOutputLevel level_ = HITRACE_LEVEL_INFO;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_DFX_H