/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef RECORDER_SERVICE_STUB_H
#define RECORDER_SERVICE_STUB_H

#include <map>
#include <set>
#include "i_standard_recorder_service.h"
#include "i_standard_recorder_listener.h"
#include "media_death_recipient.h"
#include "recorder_server.h"
#include "nocopyable.h"
#include "monitor_server_object.h"

namespace OHOS {
namespace Media {
using RecorderStubFunc = std::function<int32_t(MessageParcel &, MessageParcel &)>;
class RecorderServiceStub : public IRemoteStub<IStandardRecorderService>,
    public MonitorServerObject, public NoCopyable {
public:
    static sptr<RecorderServiceStub> Create();
    virtual ~RecorderServiceStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    int32_t SetVideoSource(VideoSourceType source, int32_t &sourceId) override;
    int32_t SetVideoEncoder(int32_t sourceId, VideoCodecFormat encoder) override;
    int32_t SetVideoSize(int32_t sourceId, int32_t width, int32_t height) override;
    int32_t SetVideoFrameRate(int32_t sourceId, int32_t frameRate) override;
    int32_t SetVideoEncodingBitRate(int32_t sourceId, int32_t rate) override;
    int32_t SetVideoIsHdr(int32_t sourceId, bool isHdr) override;
    int32_t SetVideoEnableTemporalScale(int32_t sourceId, bool enableTemporalScale) override;
    int32_t SetMetaConfigs(int32_t sourceId) override;
    int32_t SetMetaSource(MetaSourceType source, int32_t &sourceId) override;
    int32_t SetMetaMimeType(int32_t sourceId, const std::string_view &type) override;
    int32_t SetMetaTimedKey(int32_t sourceId, const std::string_view &timedKey) override;
    int32_t SetMetaSourceTrackMime(int32_t sourceId, const std::string_view &srcTrackMime) override;
    sptr<OHOS::Surface> GetSurface(int32_t sourceId) override;
    sptr<OHOS::Surface> GetMetaSurface(int32_t sourceId) override;
    int32_t SetAudioSource(AudioSourceType source, int32_t &sourceId) override;
    int32_t SetAudioEncoder(int32_t sourceId, AudioCodecFormat encoder) override;
    int32_t SetAudioSampleRate(int32_t sourceId, int32_t rate) override;
    int32_t SetAudioChannels(int32_t sourceId, int32_t num) override;
    int32_t SetAudioEncodingBitRate(int32_t sourceId, int32_t bitRate) override;
    int32_t SetDataSource(DataSourceType dataType, int32_t &sourceId) override;
    int32_t SetUserCustomInfo(Meta &userCustomInfo) override;
    int32_t SetGenre(std::string &genre) override;
    int32_t SetMaxDuration(int32_t duration) override;
    int32_t SetOutputFormat(OutputFormatType format) override;
    int32_t SetOutputFile(int32_t fd) override;
    int32_t SetLocation(float latitude, float longitude) override;
    int32_t SetOrientationHint(int32_t rotation) override;
    int32_t Prepare() override;
    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Stop(bool block) override;
    int32_t Reset() override;
    int32_t Release() override;
    int32_t DestroyStub() override;
    int32_t DumpInfo(int32_t fd);
    int32_t GetAVRecorderConfig(ConfigMap &configMap) override;
    int32_t GetLocation(Location &location) override;
    int32_t GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo) override;
    int32_t GetAvailableEncoder(std::vector<EncoderCapabilityData> &encoderInfo) override;
    int32_t GetMaxAmplitude() override;
    int32_t IsWatermarkSupported(bool &isWatermarkSupported) override;
    int32_t SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer) override;
    // MonitorServerObject override
    int32_t DoIpcAbnormality() override;
    int32_t DoIpcRecovery(bool fromMonitor) override;

private:
    RecorderServiceStub();
    int32_t Init();
    int32_t SetListenerObject(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoSource(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoEncoder(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoSize(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoFrameRate(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoEncodingBitRate(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoIsHdr(MessageParcel &data, MessageParcel &reply);
    int32_t SetVideoEnableTemporalScale(MessageParcel &data, MessageParcel &reply);
    int32_t SetMetaConfigs(MessageParcel &data, MessageParcel &reply);
    int32_t SetMetaSource(MessageParcel &data, MessageParcel &reply);
    int32_t SetMetaMimeType(MessageParcel &data, MessageParcel &reply);
    int32_t SetMetaTimedKey(MessageParcel &data, MessageParcel &reply);
    int32_t SetMetaSourceTrackMime(MessageParcel &data, MessageParcel &reply);
    int32_t GetSurface(MessageParcel &data, MessageParcel &reply);
    int32_t GetMetaSurface(MessageParcel &data, MessageParcel &reply);
    int32_t SetAudioSource(MessageParcel &data, MessageParcel &reply);
    int32_t SetAudioEncoder(MessageParcel &data, MessageParcel &reply);
    int32_t SetAudioSampleRate(MessageParcel &data, MessageParcel &reply);
    int32_t SetAudioChannels(MessageParcel &data, MessageParcel &reply);
    int32_t SetAudioEncodingBitRate(MessageParcel &data, MessageParcel &reply);
    int32_t SetDataSource(MessageParcel &data, MessageParcel &reply);
    int32_t SetMaxDuration(MessageParcel &data, MessageParcel &reply);
    int32_t SetOutputFormat(MessageParcel &data, MessageParcel &reply);
    int32_t SetOutputFile(MessageParcel &data, MessageParcel &reply);
    int32_t SetLocation(MessageParcel &data, MessageParcel &reply);
    int32_t SetOrientationHint(MessageParcel &data, MessageParcel &reply);
    int32_t SetUserCustomInfo(MessageParcel &data, MessageParcel &reply);
    int32_t SetGenre(MessageParcel &data, MessageParcel &reply);
    int32_t Prepare(MessageParcel &data, MessageParcel &reply);
    int32_t Start(MessageParcel &data, MessageParcel &reply);
    int32_t Pause(MessageParcel &data, MessageParcel &reply);
    int32_t Resume(MessageParcel &data, MessageParcel &reply);
    int32_t Stop(MessageParcel &data, MessageParcel &reply);
    int32_t Reset(MessageParcel &data, MessageParcel &reply);
    int32_t Release(MessageParcel &data, MessageParcel &reply);
    int32_t DestroyStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetAVRecorderConfig(MessageParcel &data, MessageParcel &reply);
    int32_t GetLocation(MessageParcel &data, MessageParcel &reply);
    int32_t GetCurrentCapturerChangeInfo(MessageParcel &data, MessageParcel &reply);
    int32_t GetAvailableEncoder(MessageParcel &data, MessageParcel &reply);
    int32_t GetMaxAmplitude(MessageParcel &data, MessageParcel &reply);
    int32_t IsWatermarkSupported(MessageParcel &data, MessageParcel &reply);
    int32_t SetWatermark(MessageParcel &data, MessageParcel &reply);
    int32_t CheckPermission();
    void FillRecFuncPart1();
    void FillRecFuncPart2();

    std::shared_ptr<IRecorderService> recorderServer_ = nullptr;
    std::map<uint32_t, RecorderStubFunc> recFuncs_;
    std::mutex mutex_;
    std::mutex stmutex_;
    int32_t pid_ = 0;
    AudioSourceType audioSourceType_ = AUDIO_SOURCE_INVALID;
    bool needAudioPermissionCheck = false;
    const std::set<uint32_t> AUDIO_REQUEST = {SET_AUDIO_SOURCE, SET_AUDIO_ENCODER, SET_AUDIO_ENCODER,
        SET_AUDIO_CHANNELS, SET_AUDIO_ENCODING_BIT_RATE};
    const std::set<uint32_t> COMMON_REQUEST = {SET_LISTENER_OBJ, SET_DATA_SOURCE, SET_MAX_DURATION,
        SET_OUTPUT_FORMAT, SET_OUTPUT_FILE, SET_LOCATION, SET_ORIENTATION_HINT,
        PREPARE, START, PAUSE, RESUME, STOP, RESET, RELEASE, DESTROY};
};
} // namespace Media
} // namespace OHOS
#endif // RECORDER_SERVICE_STUB_H
