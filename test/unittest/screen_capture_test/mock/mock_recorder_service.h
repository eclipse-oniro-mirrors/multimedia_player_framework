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

#ifndef MOCK_RECORDER_SERVICE_H
#define MOCK_RECORDER_SERVICE_H

#include "i_recorder_service.h"
#include "media_errors.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Media {

class MockRecorderService : public IRecorderService {
public:
    // Methods called by screen_capture_server.cpp — controllable via EXPECT_CALL
    MOCK_METHOD(int32_t, SetVideoSource, (VideoSourceType source, int32_t &sourceId), (override));
    MOCK_METHOD(int32_t, SetOutputFormat, (OutputFormatType format), (override));
    MOCK_METHOD(int32_t, SetAudioEncoder, (int32_t sourceId, AudioCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetAudioSampleRate, (int32_t sourceId, int32_t rate), (override));
    MOCK_METHOD(int32_t, SetAudioChannels, (int32_t sourceId, int32_t num), (override));
    MOCK_METHOD(int32_t, SetAudioEncodingBitRate, (int32_t sourceId, int32_t bitRate), (override));
    MOCK_METHOD(int32_t, SetVideoEncoder, (int32_t sourceId, VideoCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetVideoSize, (int32_t sourceId, int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, SetVideoFrameRate, (int32_t sourceId, int32_t frameRate), (override));
    MOCK_METHOD(int32_t, SetVideoEncodingBitRate, (int32_t sourceId, int32_t rate), (override));
    MOCK_METHOD(int32_t, SetVideoEnableBFrame, (int32_t sourceId, bool enableBFrame), (override));
    MOCK_METHOD(int32_t, SetOutputFile, (int32_t fd), (override));
    MOCK_METHOD(int32_t, SetStabilizationMode, (bool enableStabilization), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(sptr<OHOS::Surface>, GetSurface, (int32_t sourceId), (override));
    MOCK_METHOD(int32_t, SetAudioDataSource, (const std::shared_ptr<IAudioDataSource> &audioSource, int32_t &sourceId),
        (override));
    MOCK_METHOD(int32_t, Start, (), (override));
    MOCK_METHOD(int32_t, Stop, (bool block), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Resume, (), (override));
    MOCK_METHOD(int32_t, SetWatermark, (std::shared_ptr<AVBuffer> & waterMarkBuffer), (override));
    MOCK_METHOD(int32_t, AddWatermark,
        (std::shared_ptr<AVBuffer> & watermarkBuffer, int32_t width, int32_t height, int32_t &watermarkCount),
        (override));

    // Methods not called by screen_capture_server.cpp — default implementations
    int32_t SetMetaSource(MetaSourceType, int32_t &) override
    {
        return MSERR_OK;
    }
    int32_t SetMetaConfigs(int32_t) override
    {
        return MSERR_OK;
    }
    int32_t SetMetaMimeType(int32_t, const std::string_view &) override
    {
        return MSERR_OK;
    }
    int32_t SetMetaTimedKey(int32_t, const std::string_view &) override
    {
        return MSERR_OK;
    }
    int32_t SetMetaSourceTrackMime(int32_t, const std::string_view &) override
    {
        return MSERR_OK;
    }
    int32_t SetVideoIsHdr(int32_t, bool) override
    {
        return MSERR_OK;
    }
    int32_t SetVideoEnableTemporalScale(int32_t, bool) override
    {
        return MSERR_OK;
    }
    int32_t SetVideoEnableStableQualityMode(int32_t, bool) override
    {
        return MSERR_OK;
    }
    int32_t SetCaptureRate(int32_t, double) override
    {
        return MSERR_OK;
    }
    sptr<OHOS::Surface> GetMetaSurface(int32_t) override
    {
        return nullptr;
    }
    int32_t SetAudioSource(AudioSourceType, int32_t &) override
    {
        return MSERR_OK;
    }
    int32_t SetAudioAacProfile(int32_t, AacProfile) override
    {
        return MSERR_OK;
    }
    int32_t SetDataSource(DataSourceType, int32_t &) override
    {
        return MSERR_OK;
    }
    int32_t SetMaxDuration(int32_t) override
    {
        return MSERR_OK;
    }
    int32_t SetFileGenerationMode(FileGenerationMode) override
    {
        return MSERR_OK;
    }
    int32_t SetNextOutputFile(int32_t) override
    {
        return MSERR_OK;
    }
    int32_t SetMaxFileSize(int64_t) override
    {
        return MSERR_OK;
    }
    void SetLocation(float, float) override {}
    void SetOrientationHint(int32_t) override {}
    int32_t SetRecorderCallback(const std::shared_ptr<RecorderCallback> &) override
    {
        return MSERR_OK;
    }
    int32_t Reset() override
    {
        return MSERR_OK;
    }
    int32_t SetFileSplitDuration(FileSplitType, int64_t, uint32_t) override
    {
        return MSERR_OK;
    }
    int32_t SetParameter(int32_t, const Format &) override
    {
        return MSERR_OK;
    }
    int32_t GetAVRecorderConfig(ConfigMap &) override
    {
        return MSERR_OK;
    }
    int32_t GetLocation(Location &) override
    {
        return MSERR_OK;
    }
    int32_t GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &) override
    {
        return MSERR_OK;
    }
    int32_t GetAvailableEncoder(std::vector<EncoderCapabilityData> &) override
    {
        return MSERR_OK;
    }
    int32_t GetMaxAmplitude(int32_t &) override
    {
        return MSERR_OK;
    }
    int32_t SetUserCustomInfo(Meta &) override
    {
        return MSERR_OK;
    }
    int32_t SetGenre(std::string &) override
    {
        return MSERR_OK;
    }
    int32_t IsWatermarkSupported(bool &) override
    {
        return MSERR_OK;
    }
    int32_t SetUserMeta(const std::shared_ptr<Meta> &) override
    {
        return MSERR_OK;
    }
    int32_t SetWillMuteWhenInterrupted(bool) override
    {
        return MSERR_OK;
    }
    int32_t TransmitQos(QOS::QosLevel) override
    {
        return MSERR_OK;
    }
};

} // namespace Media
} // namespace OHOS

#endif // MOCK_RECORDER_SERVICE_H
