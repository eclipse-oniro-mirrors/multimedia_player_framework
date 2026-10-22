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

#ifndef TRACK_FILTER_CONVERTER_H
#define TRACK_FILTER_CONVERTER_H

#include <string>
#include "player.h"
#include "media_source.h"

namespace OHOS {
namespace Media {

class TrackFilterConverter {
public:
    static AVPlayTrackSelectionFilter ToAVPlay(const Plugins::TrackSelectionFilter& filter)
    {
        AVPlayTrackSelectionFilter result;
        result.maxVideoBitrate = filter.maxVideoBitrate;
        result.minVideoBitrate = filter.minVideoBitrate;
        result.maxVideoFrameRate = filter.maxVideoFrameRate;
        result.minVideoFrameRate = filter.minVideoFrameRate;
        result.maxVideoResolution = filter.maxVideoResolution;
        result.minVideoResolution = filter.minVideoResolution;
        result.preferredVideoMimeTypes = filter.preferredVideoMimeTypes;
        result.maxAudioBitrate = filter.maxAudioBitrate;
        result.minAudioBitrate = filter.minAudioBitrate;
        result.maxAudioChannels = filter.maxAudioChannels;
        result.preferredAudioMimeTypes = filter.preferredAudioMimeTypes;
        result.preferredAudioLanguages = filter.preferredAudioLanguages;
        result.preferredSubtitleLanguages = filter.preferredSubtitleLanguages;
        return result;
    }

    static Plugins::TrackSelectionFilter ToPlugins(const AVPlayTrackSelectionFilter& filter)
    {
        Plugins::TrackSelectionFilter result;
        result.maxVideoBitrate = filter.maxVideoBitrate;
        result.minVideoBitrate = filter.minVideoBitrate;
        result.maxVideoFrameRate = filter.maxVideoFrameRate;
        result.minVideoFrameRate = filter.minVideoFrameRate;
        result.maxVideoResolution = filter.maxVideoResolution;
        result.minVideoResolution = filter.minVideoResolution;
        result.preferredVideoMimeTypes = filter.preferredVideoMimeTypes;
        result.maxAudioBitrate = filter.maxAudioBitrate;
        result.minAudioBitrate = filter.minAudioBitrate;
        result.maxAudioChannels = filter.maxAudioChannels;
        result.preferredAudioMimeTypes = filter.preferredAudioMimeTypes;
        result.preferredAudioLanguages = filter.preferredAudioLanguages;
        result.preferredSubtitleLanguages = filter.preferredSubtitleLanguages;
        return result;
    }
};

} // namespace Media
} // namespace OHOS

#endif // TRACK_FILTER_CONVERTER_H
