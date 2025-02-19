/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "player_service_proxy_fuzzer.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include "directory_ex.h"
#include "media_parcel.h"

namespace OHOS {
namespace Media {
namespace {
    using Fuzzer = PlayerServiceProxyFuzzer;
    using PlayerStubFunc = std::function<int32_t(Fuzzer*, uint8_t*, size_t, bool)>;
    std::map<uint32_t, PlayerStubFunc> playerFuncs_ {
        {Fuzzer::SET_LISTENER_OBJ, Fuzzer::SetListenerObjectStatic},
        {Fuzzer::SET_SOURCE, Fuzzer::SetSourceStatic},
        {Fuzzer::SET_MEDIA_DATA_SRC_OBJ, Fuzzer::SetMediaDataSourceStatic},
        {Fuzzer::SET_FD_SOURCE, Fuzzer::SetFdSourceStatic},
        {Fuzzer::ADD_SUB_SOURCE, Fuzzer::AddSubSourceStatic},
        {Fuzzer::ADD_SUB_FD_SOURCE, Fuzzer::AddSubFdSourceStatic},
        {Fuzzer::PLAY, Fuzzer::PlayStatic},
        {Fuzzer::PREPARE, Fuzzer::PrepareStatic},
        {Fuzzer::PREPAREASYNC, Fuzzer::PrepareAsyncStatic},
        {Fuzzer::PAUSE, Fuzzer::PauseStatic},
        {Fuzzer::STOP, Fuzzer::StopStatic},
        {Fuzzer::RESET, Fuzzer::ResetStatic},
        {Fuzzer::RELEASE, Fuzzer::ReleaseStatic},
        {Fuzzer::SET_VOLUME, Fuzzer::SetVolumeStatic},
        {Fuzzer::SEEK, Fuzzer::SeekStatic},
        {Fuzzer::GET_CURRENT_TIME, Fuzzer::GetCurrentTimeStatic},
        {Fuzzer::GET_PLAY_BACK_POSITION, Fuzzer::GetPlaybackPositionStatic},
        {Fuzzer::GET_DURATION, Fuzzer::GetDurationStatic},
        {Fuzzer::SET_PLAYERBACK_SPEED, Fuzzer::SetPlaybackSpeedStatic},
        {Fuzzer::GET_PLAYERBACK_SPEED, Fuzzer::GetPlaybackSpeedStatic},
        {Fuzzer::SET_VIDEO_SURFACE, Fuzzer::SetVideoSurfaceStatic},
        {Fuzzer::IS_PLAYING, Fuzzer::IsPlayingStatic},
        {Fuzzer::IS_LOOPING, Fuzzer::IsLoopingStatic},
        {Fuzzer::SET_LOOPING, Fuzzer::SetLoopingStatic},
        {Fuzzer::SET_RENDERER_DESC, Fuzzer::SetParameterStatic},
        {Fuzzer::DESTROY, Fuzzer::DestroyStubStatic},
        {Fuzzer::SET_CALLBACK, Fuzzer::SetPlayerCallbackStatic},
        {Fuzzer::GET_VIDEO_TRACK_INFO, Fuzzer::GetVideoTrackInfoStatic},
        {Fuzzer::GET_AUDIO_TRACK_INFO, Fuzzer::GetAudioTrackInfoStatic},
        {Fuzzer::GET_SUBTITLE_TRACK_INFO, Fuzzer::GetSubtitleTrackInfoStatic},
        {Fuzzer::GET_VIDEO_WIDTH, Fuzzer::GetVideoWidthStatic},
        {Fuzzer::GET_VIDEO_HEIGHT, Fuzzer::GetVideoHeightStatic},
        {Fuzzer::SELECT_BIT_RATE, Fuzzer::SelectBitRateStatic},
        {Fuzzer::SELECT_TRACK, Fuzzer::SelectTrackStatic},
        {Fuzzer::DESELECT_TRACK, Fuzzer::DeselectTrackStatic},
        {Fuzzer::GET_CURRENT_TRACK, Fuzzer::GetCurrentTrackStatic},
    };
}
PlayerServiceProxyFuzzer::PlayerServiceProxyFuzzer(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardPlayerService>(impl)
{
}

sptr<PlayerServiceProxyFuzzer> PlayerServiceProxyFuzzer::Create()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = samgr->GetSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID);
    if (object == nullptr) {
        std::cout << "media object is nullptr." << std::endl;
        return nullptr;
    }
    sptr<IStandardMediaService> mediaProxy = iface_cast<IStandardMediaService>(object);
    if (mediaProxy == nullptr) {
        std::cout << "mediaProxy is nullptr." << std::endl;
        return nullptr;
    }
    sptr<IRemoteObject> listenerStub = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> playerObject = mediaProxy->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER, listenerStub);
    if (playerObject == nullptr) {
        std::cout << "playerObject is nullptr." << std::endl;
        return nullptr;
    }

    sptr<PlayerServiceProxyFuzzer> playerProxy = iface_cast<PlayerServiceProxyFuzzer>(playerObject);
    if (playerProxy == nullptr) {
        std::cout << "playerProxy is nullptr." << std::endl;
        return nullptr;
    }
    return playerProxy;
}

void PlayerServiceProxyFuzzer::SendRequest(uint32_t code, uint8_t *inputData, size_t size, bool isFuzz)
{
    auto itFunc = playerFuncs_.find(code);
    if (itFunc != playerFuncs_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            memberFunc(this, inputData, size, isFuzz);
        }
    }
}

int32_t PlayerServiceProxyFuzzer::SetListenerObjectStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_LISTENER_OBJ, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Failed to write descriptor" << std::endl;
        return false;
    }
    std::string urlStr(reinterpret_cast<const char *>(inputData), size);
    (void)data.WriteString(urlStr);
    return ptr->SendRequest(SET_SOURCE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetMediaDataSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetMediaDataSource:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_MEDIA_DATA_SRC_OBJ, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetFdSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetFdSource:Failed to write descriptor!" << std::endl;
        return false;
    }

    int32_t fdValue;
    int64_t offsetValue;
    int64_t lengthValue;
    if (isFuzz) {
        fdValue = *reinterpret_cast<int32_t *>(inputData);
        lengthValue = *reinterpret_cast<int64_t *>(inputData);
        offsetValue = *reinterpret_cast<uint32_t *>(inputData) % *reinterpret_cast<int64_t *>(inputData);
        (void)data.WriteFileDescriptor(fdValue);
        (void)data.WriteInt64(offsetValue);
        (void)data.WriteInt64(lengthValue);
        return ptr->SendRequest(SET_FD_SOURCE, data, reply, option);
    } else {
        const std::string path = "/data/test/media/H264_AAC.mp4";
        fdValue = open(path.c_str(), O_RDONLY);
        offsetValue = 0;
        if (fdValue < 0) {
            std::cout << "Open file failed" << std::endl;
            (void)close(fdValue);
            return -1;
        }

        struct stat64 buffer;
        if (fstat64(fdValue, &buffer) != 0) {
            std::cout << "Get file state failed" << std::endl;
            (void)close(fdValue);
            return -1;
        }
        lengthValue = static_cast<int64_t>(buffer.st_size);
        (void)data.WriteFileDescriptor(fdValue);
        (void)data.WriteInt64(offsetValue);
        (void)data.WriteInt64(lengthValue);
        int32_t ret = ptr->SendRequest(SET_FD_SOURCE, data, reply, option);
        (void)close(fdValue);
        return ret;
    }
}

int32_t PlayerServiceProxyFuzzer::AddSubSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "AddSubSource:Failed to write descriptor!" << std::endl;
        return false;
    }
    std::string url(reinterpret_cast<const char *>(inputData), size);
    (void)data.WriteString(url);
    return ptr->SendRequest(ADD_SUB_SOURCE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::AddSubFdSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "AddSubFdSource:Failed to write descriptor!" << std::endl;
        return false;
    }

    int32_t fdValue = *reinterpret_cast<int32_t *>(inputData);
    int64_t lengthValue = *reinterpret_cast<int64_t *>(inputData);
    int64_t offsetValue = *reinterpret_cast<uint32_t *>(inputData) % *reinterpret_cast<int64_t *>(inputData);
    (void)data.WriteFileDescriptor(fdValue);
    (void)data.WriteInt64(offsetValue);
    (void)data.WriteInt64(lengthValue);
    return ptr->SendRequest(ADD_SUB_FD_SOURCE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::PlayStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Play:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(PLAY, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::PrepareStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Prepare:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(PREPARE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::PrepareAsyncStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "PrepareAsync:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(PREPAREASYNC, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::PauseStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Pause:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(PAUSE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::StopStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Stop:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(STOP, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::ResetStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Reset:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RESET, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::ReleaseStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Release:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RELEASE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetVolumeStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetVolume:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteFloat(*reinterpret_cast<int32_t *>(inputData));
    (void)data.WriteFloat(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_VOLUME, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SeekStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Seek:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SEEK, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetCurrentTimeStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetCurrentTime:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_CURRENT_TIME, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetPlaybackPositionStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetPlaybackPosition:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_PLAY_BACK_POSITION, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetDurationStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetDuration:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_DURATION, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetPlaybackSpeedStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetPlaybackSpeed:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_PLAYERBACK_SPEED, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetPlaybackSpeedStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetPlaybackSpeed:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_PLAYERBACK_SPEED, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetVideoSurfaceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetVideoSurface:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_VIDEO_SURFACE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::IsPlayingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "IsPlaying:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(IS_PLAYING, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::IsLoopingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "IsLooping:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(IS_LOOPING, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetLoopingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
    bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetLooping:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteBool(*reinterpret_cast<int32_t *>(inputData) % 2);  // 2 true or false
    return ptr->SendRequest(SET_LOOPING, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetParameterStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_RENDERER_DESC, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::DestroyStubStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Failed to write descriptor!" << std::endl;
        return false;
    }

    if (isFuzz) {
        (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    }
    return ptr->SendRequest(DESTROY, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SetPlayerCallbackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetPlayerCallback:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_CALLBACK, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetVideoTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetVideoTrackInfo:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_VIDEO_TRACK_INFO, data, reply, option);
}


int32_t PlayerServiceProxyFuzzer::GetPlaybackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetPlaybackInfo:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_PLAYBACK_INFO, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetAudioTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetAudioTrackInfo:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_AUDIO_TRACK_INFO, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetSubtitleTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetSubtitleTrackInfo:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_SUBTITLE_TRACK_INFO, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetVideoWidthStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetVideoWidth:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_VIDEO_WIDTH, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetVideoHeightStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetVideoHeight:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_VIDEO_HEIGHT, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SelectBitRateStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SelectBitRate:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SELECT_BIT_RATE, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SelectTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SelectTrack:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SELECT_TRACK, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::DeselectTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "DeselectTrack:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(DESELECT_TRACK, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::GetCurrentTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PlayerServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetCurrentTrack:Failed to write descriptor!" << std::endl;
        return false;
    }

    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(GET_CURRENT_TRACK, data, reply, option);
}

int32_t PlayerServiceProxyFuzzer::SendRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return Remote()->SendRequest(code, data, reply, option);
}
}
}