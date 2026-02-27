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

#include "lpp_video_streamer_service_proxy.h"

#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "media_dfx.h"

#include "string_ex.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoStreamerServiceProxy"};
}

namespace OHOS {
namespace Media {

LppVideoStreamerServiceProxy::LppVideoStreamerServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardLppVideoStreamerService>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppVideoStreamerServiceProxy::~LppVideoStreamerServiceProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppVideoStreamerServiceProxy::Init(const std::string &mime)
{
    MEDIA_LOGD("LppVideoStreamerServiceProxy::Init");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteString(mime);

    Remote()->SendRequest(INIT, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetParameter(const Format &param)
{
    MEDIA_LOGD("LppVideoStreamerServiceProxy::SetParameter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    MediaParcel::Marshalling(data, param);

    Remote()->SendRequest(SET_PARAMETER, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::GetParameter(Format &param)
{
    MEDIA_LOGD("LppVideoStreamerServiceProxy::GetParameter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
    Remote()->SendRequest(GET_PARAMETER, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32() == MSERR_OK, MSERR_INVALID_OPERATION, "Failed to SendRequest!");
    bool ret = MediaParcel::MetaUnmarshalling(reply, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to MetaUnMarshalling format!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceProxy::Configure(const Format &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    MediaParcel::Marshalling(data, param);

    int32_t error = Remote()->SendRequest(CONFIGURE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION, "Configure failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Prepare()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(PREPARE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Start()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(START, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Pause()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(PAUSE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Resume()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RESUME, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Flush()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(FLUSH, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Stop()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(STOP, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Reset()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RESET, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    Remote()->SendRequest(RELEASE, data, reply, option);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::StartDecode()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(START_DECODE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "StartDecode failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::StartRender()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(START_RENDER, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "StartRender failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetOutputSurface(sptr<Surface> surface)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_OPERATION, "Surface is nullptr");
    sptr<IBufferProducer> producer = surface->GetProducer();
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_INVALID_OPERATION, "Producer is nullptr");

    sptr<IRemoteObject> object = producer->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_INVALID_OPERATION, "Object is nullptr");

    const std::string surfaceFormat = "SURFACE_FORMAT";
    std::string format = surface->GetUserData(surfaceFormat);
    MEDIA_LOGD("Surface format is %{public}s!", format.c_str());

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Write descriptor failed!");

    bool parcelRet = data.WriteRemoteObject(object);
    parcelRet = parcelRet && data.WriteString(format);
    CHECK_AND_RETURN_RET_LOG(parcelRet, MSERR_INVALID_OPERATION, "Write parcel failed");

    int32_t ret = Remote()->SendRequest(SET_OUTPUT_SURFACE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        ret == MSERR_OK, MSERR_INVALID_OPERATION, "SetSyncAudioStreamer failed, error: %{public}d", ret);

    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetSyncAudioStreamer(AudioStreamer *audioStreamer)
{
    (void)audioStreamer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(SET_SYNC_AUDIO_STREAMER, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "SetSyncAudioStreamer failed, error: %{public}d", error);
    return reply.ReadInt32();
}
int32_t LppVideoStreamerServiceProxy::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteInt64(targetPts);
    data.WriteInt32(timeoutMs);
    int32_t error = Remote()->SendRequest(SET_TARGET_START_FRAME, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "SetTargetStartFrame failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetVolume(float volume)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteFloat(volume);

    int32_t error = Remote()->SendRequest(SET_VOLUME, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION, "SetVolume failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetPlaybackSpeed(float speed)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteFloat(speed);

    int32_t error = Remote()->SendRequest(SET_PLAYBACK_SPEED, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetPlaybackSpeed failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");
    framePacket->WriteToMessageParcel(data);
    int32_t error = Remote()->SendRequest(RETURN_FRAMES, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "ReturnFrames failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::RegisterCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(REGISTER_CALLBACK, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "RegisterCallback failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("LppVideoStreamerServiceProxy::SetListenerObject");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteRemoteObject(object);
    int32_t error = Remote()->SendRequest(SET_LISTENER_OBJ, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "SetListenerObject failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::SetLppVideoStreamerCallback()
{
    MediaTrace trace("LppVideoStreamerServiceProxy::SetPlayerCallback");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(SET_AUDIO_STREAM_CALLBACK, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "SetLppVideoStreamerCallback failed, error: %{public}d", error);

    return reply.ReadInt32();
}

std::string LppVideoStreamerServiceProxy::GetStreamerId()
{
    MediaTrace trace("LppVideoStreamerServiceProxy::GetStreamerId");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, "", "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(GET_STREAM_ID, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, "", "GetStreamerId failed, error: %{public}d", error);
    std::string key = reply.ReadString();
    return key;
}

int32_t LppVideoStreamerServiceProxy::SetLppAudioStreamerId(const std::string audioStreamId)
{
    MediaTrace trace("LppVideoStreamerServiceProxy::SetLppAudioStreamerId");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteString(audioStreamId);
    int32_t error = Remote()->SendRequest(SET_AUDIO_STREAMER_ID, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "SetLppAudioStreamerCallback failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::RenderFirstFrame()
{
    MediaTrace trace("LppVideoStreamerServiceProxy::RenderFirstFrame");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(RENDER_FIRST_FRAME, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "RenderFirstFrame failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t LppVideoStreamerServiceProxy::GetLatestPts(int64_t &pts)
{
    MEDIA_LOGI("LppVideoStreamerServiceProxy GetLatestPts");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(LppVideoStreamerServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(GET_LATEST_PTS, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(
        error == MSERR_OK, MSERR_INVALID_OPERATION, "GetLatestPts SendRequest failed, error: %{public}d", error);
    int32_t ret = reply.ReadInt32();
    pts = reply.ReadInt64();
    CHECK_AND_RETURN_RET_LOG(
        ret == MSERR_OK, MSERR_INVALID_OPERATION, "GetLatestPts failed, error: %{public}d", ret);
    return ret;
}
}  // namespace Media
}  // namespace OHOS
