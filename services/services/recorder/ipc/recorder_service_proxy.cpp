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

#include "recorder_service_proxy.h"
#include "recorder_listener_stub.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderServiceProxy"};
}

namespace OHOS {
namespace Media {
RecorderServiceProxy::RecorderServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardRecorderService>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderServiceProxy::~RecorderServiceProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t TransformServiceStubErrCode(int32_t stubErrCode)
{
    static const std::unordered_map<int32_t, int32_t> map = {
        {MSERR_OK,                      MSERR_OK},
        {MSERR_NO_PERMISSION_5400102,   MSERR_NO_PERMISSION_5400102},
        {MSERR_NULL_POINTER_5400101,    MSERR_NULL_POINTER_5400101},
    };
    auto it = map.find(stubErrCode);
    if (it != map.end()) {
        return it->second;
    }
    return MSERR_INVALID_OPERATION;
}

int32_t RecorderServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteRemoteObject(object);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write RemoteObject!");

    int ret = Remote()->SendRequest(SET_LISTENER_OBJ, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, error, "SetListenerObject failed, error: %{public}d", ret);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoSource(VideoSourceType source, int32_t &sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(source);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write source!");

    int ret = Remote()->SendRequest(SET_VIDEO_SOURCE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoSource failed, error: %{public}d", error);

    sourceId = reply.ReadInt32();
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoEncoder(int32_t sourceId, VideoCodecFormat encoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(encoder);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_ENCODER, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoEncoder failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoSize(int32_t sourceId, int32_t width, int32_t height)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(width) && data.WriteInt32(height);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_SIZE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoSize failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoFrameRate(int32_t sourceId, int32_t frameRate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(frameRate);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_FRAME_RATE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoFrameRate failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoEncodingBitRate(int32_t sourceId, int32_t rate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(rate);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_ENCODING_BIT_RATE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoEncodingBitRate failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoIsHdr(int32_t sourceId, bool isHdr)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteBool(isHdr);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_IS_HDR, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoIsHdr failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoEnableTemporalScale(int32_t sourceId, bool enableTemporalScale)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteBool(enableTemporalScale);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_VIDEO_ENABLE_TEMPORAL_SCALE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoEnableTemporalScale failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoEnableStableQualityMode(int32_t sourceId, bool enableStableQualityMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
 
    token = data.WriteInt32(sourceId) && data.WriteBool(enableStableQualityMode);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");
 
    int ret = Remote()->SendRequest(SET_VIDEO_ENABLE_STABLE_QUALITY_MODE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error,
        "SetVideoEnableStableQualityMode failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetVideoEnableBFrame(int32_t sourceId, bool enableBFrame)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
 
    token = data.WriteInt32(sourceId) && data.WriteBool(enableBFrame);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");
 
    int ret = Remote()->SendRequest(SET_VIDEO_ENABLE_B_FRAME, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetVideoEnableBFrame failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMetaConfigs(int32_t sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_META_CONFIGS, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMetaConfigs failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMetaSource(MetaSourceType source, int32_t &sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(source);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_META_SOURCE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMetaSource failed, error: %{public}d", error);

    sourceId = reply.ReadInt32();
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMetaMimeType(int32_t sourceId, const std::string_view &type)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteCString(type.data());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_META_MIME_TYPE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMetaMimeType failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMetaTimedKey(int32_t sourceId, const std::string_view &timedKey)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteCString(timedKey.data());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_META_TIMED_KEY, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMetaTimedKey failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMetaSourceTrackMime(int32_t sourceId, const std::string_view &srcTrackMime)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteCString(srcTrackMime.data());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_META_TRACK_SRC_MIME_TYPE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMetaSourceTrackMime failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetCaptureRate(int32_t sourceId, double fps)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteDouble(fps);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_CAPTURE_RATE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetCaptureRate failed, error: %{public}d", error);

    return reply.ReadInt32();
}

sptr<OHOS::Surface> RecorderServiceProxy::GetSurface(int32_t sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId);
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "write data failed");

    int error = Remote()->SendRequest(GET_SURFACE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "GetSurface failed, error: %{public}d", error);

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to read surface object");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, nullptr, "failed to convert object to producer");

    return OHOS::Surface::CreateSurfaceAsProducer(producer);
}

sptr<OHOS::Surface> RecorderServiceProxy::GetMetaSurface(int32_t sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId);
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "write data failed");

    int error = Remote()->SendRequest(GET_META_SURFACE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "GetMetaSurface failed, error: %{public}d", error);

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to read surface object");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, nullptr, "failed to convert object to producer");

    return OHOS::Surface::CreateSurfaceAsProducer(producer);
}

int32_t RecorderServiceProxy::SetAudioSource(AudioSourceType source, int32_t &sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(static_cast<int32_t>(source));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_SOURCE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioSource failed, error: %{public}d", error);

    sourceId = reply.ReadInt32();
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetAudioEncoder(int32_t sourceId, AudioCodecFormat encoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(static_cast<int32_t>(encoder));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_ENCODER, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioEncoder failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetAudioSampleRate(int32_t sourceId, int32_t rate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(rate);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_SAMPLE_RATE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioSampleRate failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetAudioChannels(int32_t sourceId, int32_t num)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(num);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_CHANNELS, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioChannels failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetAudioEncodingBitRate(int32_t sourceId, int32_t bitRate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(bitRate);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_ENCODING_BIT_RATE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioEncodingBitRate failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetAudioAacProfile(int32_t sourceId, AacProfile aacProfile)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(sourceId) && data.WriteInt32(static_cast<int32_t>(aacProfile));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_AUDIO_AACPROFILE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetAudioAacProfile failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetDataSource(DataSourceType dataType, int32_t &sourceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(static_cast<int32_t>(dataType));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_DATA_SOURCE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetDataSource failed, error: %{public}d", error);

    sourceId = reply.ReadInt32();
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetUserCustomInfo(Meta &userCustomInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    bool ret = userCustomInfo.ToParcel(data);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_IPC_ERROR_5400102, "userCustomInfo ToParcel failed");
    int stubError = Remote()->SendRequest(SET_USER_CUSTOM_INFO, data, reply, option);
    int32_t error = TransformServiceStubErrCode(stubError);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetUserCustomInfo failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetGenre(std::string &genre)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteString(genre);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_GENRE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetGenre failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMaxDuration(int32_t duration)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(duration);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_MAX_DURATION, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMaxDuration failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetOutputFormat(OutputFormatType format)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(static_cast<int32_t>(format));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_OUTPUT_FORMAT, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetOutputFormat failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetOutputFile(int32_t fd)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteFileDescriptor(fd);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write FileDescriptor failed");

    int ret = Remote()->SendRequest(SET_OUTPUT_FILE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetOutputFile failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetFileGenerationMode(FileGenerationMode mode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
 
    token = data.WriteInt32(static_cast<int32_t>(mode));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_FILE_GENERATION_MODE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetFileGenerationMode failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetNextOutputFile(int32_t fd)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteFileDescriptor(fd);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_NEXT_OUTPUT_FILE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetNextOutputFile failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetMaxFileSize(int64_t size)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt64(size);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_MAX_FILE_SIZE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetMaxFileSize failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetLocation(float latitude, float longitude)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteFloat(latitude) && data.WriteFloat(longitude);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_LOCATION, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetLocation failed, error: %{public}d", error);
    return MSERR_OK;
}

int32_t RecorderServiceProxy::SetOrientationHint(int32_t rotation)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(rotation);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_ORIENTATION_HINT, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetOrientationHint failed, error: %{public}d", error);
    return MSERR_OK;
}

int32_t RecorderServiceProxy::Prepare()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(PREPARE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Prepare failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(START, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Start failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Pause()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(PAUSE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Pause failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Resume()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(RESUME, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Resume failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Stop(bool block)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteBool(block);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(STOP, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Stop failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Reset()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(RESET, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Reset failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(RELEASE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Release failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetFileSplitDuration(FileSplitType type, int64_t timestamp, uint32_t duration)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    token = data.WriteInt32(static_cast<int32_t>(type)) && data.WriteInt64(timestamp) && data.WriteUint32(duration);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_FILE_SPLIT_DURATION, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetFileSplitDuration failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::DestroyStub()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(DESTROY, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "DestroyStub failed, error: %{public}d", error);

    return reply.ReadInt32();
}
int32_t RecorderServiceProxy::GetAVRecorderConfig(ConfigMap &configMap)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(GET_AV_RECORDER_CONFIG, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "GetAVRecorderConfig failed, error: %{public}d", error);

    configMap["audioBitrate"] = reply.ReadInt32();
    configMap["audioChannels"] = reply.ReadInt32();
    configMap["audioCodec"] = reply.ReadInt32();
    configMap["audioSampleRate"] = reply.ReadInt32();
    configMap["fileFormat"] = reply.ReadInt32();
    configMap["videoBitrate"] = reply.ReadInt32();
    configMap["videoCodec"] = reply.ReadInt32();
    configMap["videoFrameHeight"] = reply.ReadInt32();
    configMap["videoFrameWidth"] = reply.ReadInt32();
    configMap["videoFrameRate"] = reply.ReadInt32();
    configMap["audioSourceType"] = reply.ReadInt32();
    configMap["videoSourceType"] = reply.ReadInt32();
    configMap["url"] = reply.ReadInt32();
    configMap["rotation"] = reply.ReadInt32();
    configMap["withVideo"] = reply.ReadInt32();
    configMap["withAudio"] = reply.ReadInt32();
    configMap["withLocation"] = reply.ReadInt32();

    return MSERR_OK;
}

int32_t RecorderServiceProxy::GetLocation(Location &location)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(GET_LOCATION, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "GetAVRecorderConfig failed, error: %{public}d", error);

    location.latitude = reply.ReadFloat();
    location.longitude = reply.ReadFloat();
    return MSERR_OK;
}

int32_t RecorderServiceProxy::GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(GET_AUDIO_CAPTURER_CHANGE_INFO, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "GetCurrentCapturerChangeInfo failed, error: %{public}d", error);
    changeInfo.Unmarshalling(reply);
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::GetAvailableEncoder(std::vector<EncoderCapabilityData> &encoderInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(GET_AVAILABLE_ENCODER, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "GetAvailableEncoder failed, error: %{public}d", error);
    int32_t encoderCnt = reply.ReadInt32();
    int32_t codecFormatCntMax = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT + VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT;
    CHECK_AND_RETURN_RET_LOG(0 < encoderCnt && encoderCnt < codecFormatCntMax,
        MSERR_GET_AVAILABLE_ENCODERS_SIZE_ERROR_5400102,
        "The number of returned encoders is out of range, encoderCnt: %{public}d, codecFormatCntMax: %{public}d",
        encoderCnt, codecFormatCntMax);
    for (int32_t i = 0; i < encoderCnt; i++) {
        EncoderCapabilityData codecData;
        codecData.Unmarshalling(reply);
        encoderInfo.push_back(codecData);
    }
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::GetMaxAmplitude(int32_t &amplitude)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(GET_MAX_AMPLITUDE, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "GetMaxAmplitude failed, error: %{public}d", error);
    amplitude = reply.ReadInt32();
    MEDIA_LOGI("GetMaxAmplitude amplitude result: %{public}d", amplitude);
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::IsWatermarkSupported(bool &isWatermarkSupported)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");

    int ret = Remote()->SendRequest(IS_WATERMARK_SUPPORTED, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "IsWatermarkSupported failed, error: %{public}d", error);
    isWatermarkSupported = reply.ReadBool();
    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
    
    CHECK_AND_RETURN_RET_LOG(waterMarkBuffer->WriteToMessageParcel(data),
        MSERR_IPC_ERROR_5400102, "Failed to write waterMarkBuffer!");

    int ret = Remote()->SendRequest(SET_WATERMARK, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetWatermark failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer, int32_t width, int32_t height,
    int32_t &watermarkCount)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
    CHECK_AND_RETURN_RET_LOG(watermarkBuffer->WriteToMessageParcel(data),
        MSERR_IPC_ERROR_5400102, "Failed to write watermarkBuffer!");

    token = data.WriteInt32(width) && data.WriteInt32(height);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int32_t ret = Remote()->SendRequest(ADD_WATERMARK, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "AddWatermark failed, error: %{public}d", error);

    watermarkCount = reply.ReadInt32();
    ret = reply.ReadInt32();
    return ret;
}

int32_t RecorderServiceProxy::SetUserMeta(const std::shared_ptr<Meta> &userMeta)
{
    (void)userMeta;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
    
    CHECK_AND_RETURN_RET_LOG(userMeta->ToParcel(data), MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_USERMETA, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetUserMeta failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::SetWillMuteWhenInterrupted(bool muteWhenInterrupted)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
    
    token = data.WriteBool(muteWhenInterrupted);
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(SET_INTERRUPT_STRATEGY, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "SetWillMuteWhenInterrupted failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t RecorderServiceProxy::TransmitQos(QOS::QosLevel level)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(RecorderServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "Failed to write descriptor!");
    
    token = data.WriteInt32(static_cast<int32_t>(level));
    CHECK_AND_RETURN_RET_LOG(token, MSERR_IPC_ERROR_5400102, "write data failed");

    int ret = Remote()->SendRequest(TRANSMIT_QOS, data, reply, option);
    int32_t error = TransformServiceStubErrCode(ret);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "TransmitQos failed, error: %{public}d", error);

    return reply.ReadInt32();
}
} // namespace Media
} // namespace OHOS
