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

#include "lpp_audio_streamer_service_proxy.h"

#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "media_dfx.h"

#include "string_ex.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioStreamerServiceProxy"};
}

namespace OHOS {
namespace Media {

LppAudioStreamerServiceProxy::LppAudioStreamerServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardLppAudioStreamerService>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    // playerFuncs_[SET_SOURCE] = "Player::SetSource";
}

LppAudioStreamerServiceProxy::~LppAudioStreamerServiceProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppAudioStreamerServiceProxy::Init(const std::string &mime)
{
    MEDIA_LOGD("LppAudioStreamerServiceProxy::Init");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteString(mime);

    Remote()->SendRequest(INIT, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetParameter(const Format &param)
{
    MEDIA_LOGD("LppAudioStreamerServiceProxy::SetParameter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    bool ret = MediaParcel::MetaMarshalling(data, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to parcel format!");

    Remote()->SendRequest(SET_PARAMETER, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::GetParameter(Format &param)
{
    MEDIA_LOGD("LppAudioStreamerServiceProxy::GetParameter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
    Remote()->SendRequest(GET_PARAMETER, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32() == MSERR_OK, MSERR_INVALID_OPERATION, "Failed to SendRequest!");
    bool ret = MediaParcel::MetaUnmarshalling(reply, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to MetaUnMarshalling format!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceProxy::Configure(const Format &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    bool ret = MediaParcel::MetaMarshalling(data, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to parcel format!");

    int32_t error = Remote()->SendRequest(CONFIGURE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "Configure failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Prepare()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(PREPARE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(START, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Pause()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(PAUSE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Resume()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RESUME, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Flush()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(FLUSH, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(STOP, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::Reset()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RESET, data, reply, option);
    return reply.ReadInt32();
}


int32_t LppAudioStreamerServiceProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RELEASE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetVolume(float volume)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteFloat(volume);

    int32_t error = Remote()->SendRequest(SET_VOLUME, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetVolume failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetLoudnessGain(const float loudnessGain)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteFloat(loudnessGain);

    int32_t error = Remote()->SendRequest(SET_LOUDNESS_GAIN, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetLoudnessGain failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetPlaybackSpeed(float speed)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteFloat(speed);

    int32_t error = Remote()->SendRequest(SET_PLAYBACK_SPEED, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetPlaybackSpeed failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
    framePacket->WriteToMessageParcel(data);

    Remote()->SendRequest(RETURN_FRAMES, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::RegisterCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(REGISTER_CALLBACK, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("LppAudioStreamerServiceProxy::SetListenerObject");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
 
    (void)data.WriteRemoteObject(object);
    int32_t error = Remote()->SendRequest(SET_LISTENER_OBJ, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetListenerObject failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}
 
int32_t LppAudioStreamerServiceProxy::SetLppAudioStreamerCallback()
{
    MediaTrace trace("LppAudioStreamerServiceProxy::SetPlayerCallback");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
 
    int32_t error = Remote()->SendRequest(SET_AUDIO_STREAM_CALLBACK, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetLppAudioStreamerCallback failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}

int32_t LppAudioStreamerServiceProxy::SetLppVideoStreamerId(const std::string videoStreamId)
{
    MediaTrace trace("LppAudioStreamerServiceProxy::SetLppVideoStreamerId");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteString(videoStreamId);
    int32_t error = Remote()->SendRequest(SET_VIDOE_STREAMER_ID, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetLppAudioStreamerCallback failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}

std::string LppAudioStreamerServiceProxy::GetStreamerId()
{
    MediaTrace trace("LppAudioStreamerServiceProxy::GetStreamerId");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(LppAudioStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, "", "Failed to write descriptor!");
 
    int32_t error = Remote()->SendRequest(GET_STREAM_ID, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, "",
        "GetStreamerId failed, error: %{public}d", error);
    std::string key = reply.ReadString();
    return key;
}


} // namespace Media
} // namespace OHOS
