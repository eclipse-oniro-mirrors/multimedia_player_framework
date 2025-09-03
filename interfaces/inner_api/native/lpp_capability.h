/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef LPP_CAPABILITY_H
#define LPP_CAPABILITY_H

#include <refbase.h>
#ifdef SUPPORT_LPP_VIDEO_STRAMER
#include "v1_0/ilow_power_player_factory.h"
namespace PlayerHDI = OHOS::HDI::LowPowerPlayer::V1_0;
#endif

namespace OHOS {
namespace Media {
struct VideoMimeCapIpc : public Parcelable {
public:
    std::string mime_ = "";                              /** video/avc, video/hevc */
    uint32_t minWidth_ = 0;
    uint32_t minHeight_ = 0;
    uint32_t maxWidth_ = 0;
    uint32_t maxHeight_ = 0;
    uint32_t maxPixelPerSecond_ = 0;
    uint32_t maxInstance_ = 0;
    bool isSupportDRM_ = false;
    std::vector<uint32_t> supportHDRTypes_ = {};             /** HDR10, HDR10+, HDRVivid */
#ifdef SUPPORT_LPP_VIDEO_STRAMER
    VideoMimeCapIpc(const PlayerHDI::VideoMimeCap &videoMimeCap)
    {
        mime_ = videoMimeCap.mime;
        minWidth_ = videoMimeCap.minWidth;
        minHeight_ = videoMimeCap.minHeight;
        maxWidth_ = videoMimeCap.maxWidth;
        maxHeight_ = videoMimeCap.maxHeight;
        maxPixelPerSecond_ = videoMimeCap.maxPixelPerSecond;
        maxInstance_ = videoMimeCap.maxInstance;
        isSupportDRM_ = videoMimeCap.isSupportDRM;
        for (uint32_t i = 0; i < videoMimeCap.supportHDRTypes.size(); i++) {
            supportHDRTypes_.push_back(videoMimeCap.supportHDRTypes[i]);
        }
    }
#endif

    VideoMimeCapIpc() {}

    bool Marshalling(Parcel &parcel) const override
    {
        parcel.WriteString(mime_);
        parcel.WriteUint32(minWidth_);
        parcel.WriteUint32(minHeight_);
        parcel.WriteUint32(maxWidth_);
        parcel.WriteUint32(maxHeight_);
        parcel.WriteUint32(maxPixelPerSecond_);
        parcel.WriteUint32(maxInstance_);
        parcel.WriteBool(isSupportDRM_);
        uint32_t typeSize = supportHDRTypes_.size();
        parcel.WriteUint32(typeSize);
        for (uint32_t i = 0; i < typeSize; i++) {
            parcel.WriteUint32(supportHDRTypes_[i]);
        }
        return true;
    }

    void UnmarshallingSelf(Parcel &parcel)
    {
        mime_ = parcel.ReadString();
        minWidth_ = parcel.ReadUint32();
        minHeight_ = parcel.ReadUint32();
        maxWidth_ = parcel.ReadUint32();
        maxHeight_ = parcel.ReadUint32();
        maxPixelPerSecond_ = parcel.ReadUint32();
        maxInstance_ = parcel.ReadUint32();
        isSupportDRM_ = parcel.ReadBool();
        uint32_t typeSize = parcel.ReadUint32();
        for (uint32_t i = 0; i < typeSize; i++) {
            supportHDRTypes_.push_back(parcel.ReadUint32());
        }
    }
};

struct AudioMimeCapIpc : public Parcelable {
public:
    std::string mime_ = "";                               /** AAC, Flac, Vorbis, MPEG, G711mu, AMR(amrnb, amrwb), APE */
    uint32_t sampleRate_ = 0;
    uint32_t channelCount_ = 0;
#ifdef SUPPORT_LPP_VIDEO_STRAMER
    AudioMimeCapIpc(const PlayerHDI::AudioMimeCap &audioMimeCap)
    {
        mime_ = audioMimeCap.mime;
        sampleRate_ = audioMimeCap.sampleRate;
        channelCount_ = audioMimeCap.channelCount;
    }
#endif

    AudioMimeCapIpc() {}

    bool Marshalling(Parcel &parcel) const override
    {
        parcel.WriteString(mime_);
        parcel.WriteUint32(sampleRate_);
        parcel.WriteUint32(channelCount_);
        return true;
    }

    void UnmarshallingSelf(Parcel &parcel)
    {
        mime_ = parcel.ReadString();
        sampleRate_ = parcel.ReadUint32();
        channelCount_ = parcel.ReadUint32();
    }
};

struct LppAvCapabilityInfo : public Parcelable {
public:
    uint32_t maxInstance_ = 0;
    std::vector<VideoMimeCapIpc> videoCap_ = {};           /** videoCap */
    std::vector<AudioMimeCapIpc> audioCap_ = {};
    
    LppAvCapabilityInfo() {}

#ifdef SUPPORT_LPP_VIDEO_STRAMER
    void SetLppAvCapabilityInfo(PlayerHDI::LppAVCap &lppAVCap)
    {
        maxInstance_ = lppAVCap.maxInstance;
        for (uint32_t i = 0; i < lppAVCap.videoCap.size(); i++) {
            VideoMimeCapIpc videoMimeCapIpc(lppAVCap.videoCap[i]);
            videoCap_.push_back(videoMimeCapIpc);
        }

        for (uint32_t i = 0; i < lppAVCap.audioCap.size(); i++) {
            AudioMimeCapIpc audioMimeCapIpc(lppAVCap.audioCap[i]);
            audioCap_.push_back(audioMimeCapIpc);
        }
    }
#endif

    bool Marshalling(Parcel &parcel) const override
    {
        parcel.WriteUint32(maxInstance_);

        parcel.WriteUint32(videoCap_.size());
        for (uint32_t i = 0; i< videoCap_.size(); i++) {
            videoCap_[i].Marshalling(parcel);
        }

        parcel.WriteUint32(audioCap_.size());
        for (uint32_t i = 0; i< audioCap_.size(); i++) {
            audioCap_[i].Marshalling(parcel);
        }
        return true;
    }

    static LppAvCapabilityInfo Unmarshalling(Parcel &parcel)
    {
        const uint32_t MAX_SIZE = 65535;
        LppAvCapabilityInfo info;
        info.maxInstance_ = parcel.ReadUint32();

        uint32_t videoCapSize = parcel.ReadUint32();
        if (videoCapSize > MAX_SIZE) {
            return info;
        }
        for (uint32_t i = 0; i< videoCapSize; i++) {
            VideoMimeCapIpc videoCap;
            videoCap.UnmarshallingSelf(parcel);
            info.videoCap_.push_back(videoCap);
        }

        uint32_t audioCapSize = parcel.ReadUint32();
        if (audioCapSize > MAX_SIZE) {
            return info;
        }
        for (uint32_t i = 0; i< audioCapSize; i++) {
            AudioMimeCapIpc audioCap;
            audioCap.UnmarshallingSelf(parcel);
            info.audioCap_.push_back(audioCap);
        }
        return info;
    }
};
}
}
#endif  // LPP_CAPABILITY_H