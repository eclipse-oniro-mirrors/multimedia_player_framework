/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cmath>
#include <iostream>
#include "aw_common.h"
#include <cstdint>
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "media_server_manager.h"
#include "mediaservermanager_fuzzer.h"
#include "test_template.h"
#include "ipc_skeleton.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
MediaServerManagerFuzzer::MediaServerManagerFuzzer()
{
}

MediaServerManagerFuzzer::~MediaServerManagerFuzzer()
{
}

void MediaServerManagerFuzzer::FuzzMediaServerManagerAll(uint8_t *data, size_t size)
{
    FuzzMediaServerManagerResetAllProxy(data, size);
    FuzzMediaServerManagerFreezeStubForPids(data, size);
    FuzzMediaServerManagerCreateRecorder(data, size);
    FuzzMediaServerManagerMonitorAndCodec(data, size);
    FuzzCanKillMediaService(data, size);
    FuzzSetClearCallBack(data, size);
    FuzzReportAppMemoryUsage(data, size);
    FuzzDestroyDumperForPid(data, size);
    FuzzGetPlayerPids(data, size);
}

void MediaServerManagerFuzzer::FuzzMediaServerManagerResetAllProxy(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.ResetAllProxy();

    int kPlayerCount = GetData<int32_t>();
    constexpr int32_t maxPlayerCount = 3;
    int32_t playerCount = kPlayerCount % (maxPlayerCount + 1);

    for (int i = 0; i < playerCount; ++i) {
        (void)mediaServerManager.CreateStubObject(MediaServerManager::StubType::PLAYER);
    }
    (void)mediaServerManager.ResetAllProxy();
}

void MediaServerManagerFuzzer::FuzzMediaServerManagerFreezeStubForPids(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    (void)size;

    MediaServerManager &mediaServerManager = MediaServerManager::GetInstance();

    std::set<int32_t> emptyPidList;
    (void)mediaServerManager.FreezeStubForPids(emptyPidList, true);

    uint32_t rawCount = GetData<uint32_t>();
    constexpr uint32_t maxPlayerCount = 3;
    uint32_t playerCount = rawCount % (maxPlayerCount + 1);
    for (uint32_t i = 0; i < playerCount; ++i) {
        (void)mediaServerManager.CreateStubObject(MediaServerManager::StubType::PLAYER);
    }

    std::set<int32_t> pidList;
    int32_t basePid = IPCSkeleton::GetCallingPid();
    pidList.insert(basePid);

    uint32_t extraPidCount = GetData<uint32_t>() % 3;
    for (uint32_t i = 0; i < extraPidCount; ++i) {
        int32_t delta = static_cast<int32_t>(GetData<uint32_t>() % 16) + 1;
        pidList.insert(basePid + delta);
    }

    bool isProxy = (GetData<uint8_t>() & 0x1) != 0;
    (void)mediaServerManager.FreezeStubForPids(pidList, isProxy);
    (void)mediaServerManager.FreezeStubForPids(pidList, !isProxy);
}

void MediaServerManagerFuzzer::FuzzMediaServerManagerCreateRecorder(uint8_t *data, size_t size)
{
    MediaServerManager &mediaServerManager = MediaServerManager::GetInstance();
    uint32_t rawCount = GetData<uint32_t>();
    constexpr uint32_t maxRecorderCount = 3;
    uint32_t recorderCount = rawCount % (maxRecorderCount + 1);
    for (uint32_t i = 0; i < recorderCount; ++i) {
        sptr<IRemoteObject> obj = mediaServerManager.CreateStubObject(MediaServerManager::StubType::RECORDER);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::RECORDER, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::RECORDER, obj);
        }
    }
    uint32_t rawProfilesCount = GetData<uint32_t>();
    constexpr uint32_t maxProfilesCount = 20;
    uint32_t profilesCount = rawProfilesCount % (maxProfilesCount + 1);
    for (uint32_t i = 0; i < profilesCount; ++i) {
        sptr<IRemoteObject> obj = mediaServerManager.CreateStubObject(MediaServerManager::StubType::RECORDERPROFILES);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::RECORDERPROFILES, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::RECORDERPROFILES, obj);
        }
    }
    uint32_t rawScCount = GetData<uint32_t>();
    constexpr uint32_t maxScCount = 3;
    uint32_t screenCaptureCount = rawScCount % (maxScCount + 1);
    for (uint32_t i = 0; i < screenCaptureCount; ++i) {
        sptr<IRemoteObject> obj = mediaServerManager.CreateStubObject(MediaServerManager::StubType::SCREEN_CAPTURE);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE, obj);
        }
    }
    for (uint32_t i = 0; i < screenCaptureCount; ++i) {
        sptr<IRemoteObject> obj = mediaServerManager.CreateStubObject(
            MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, obj);
        }
    }
    for (uint32_t i = 0; i < screenCaptureCount; ++i) {
        sptr<IRemoteObject> obj = mediaServerManager.CreateStubObject(
            MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER, obj);
        }
    }
}

void MediaServerManagerFuzzer::FuzzMediaServerManagerMonitorAndCodec(uint8_t *data, size_t size)
{
    MediaServerManager &mediaServerManager = MediaServerManager::GetInstance();

    (void)mediaServerManager.CreateStubObject(MediaServerManager::StubType::MONITOR);
    uint32_t rawCodecCount = GetData<uint32_t>();
    constexpr uint32_t maxCodecCount = 3;
    uint32_t codecCount = rawCodecCount % (maxCodecCount + 1);

    for (uint32_t i = 0; i < codecCount; ++i) {
        sptr<IRemoteObject> obj =
            mediaServerManager.CreateStubObject(MediaServerManager::StubType::AVCODEC);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::AVCODEC, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::AVCODEC, obj);
        }
    }

    uint32_t rawCodecListCount = GetData<uint32_t>();
    uint32_t codecListCount = rawCodecListCount % (maxCodecCount + 1);

    for (uint32_t i = 0; i < codecListCount; ++i) {
        sptr<IRemoteObject> obj =
            mediaServerManager.CreateStubObject(MediaServerManager::StubType::AVCODECLIST);
        if (obj != nullptr) {
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::AVCODECLIST, obj);
            mediaServerManager.DestroyStubObject(MediaServerManager::StubType::AVCODECLIST, obj);
        }
    }
}

void MediaServerManagerFuzzer::FuzzCanKillMediaService(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.CanKillMediaService();
}

void MediaServerManagerFuzzer::FuzzSetClearCallBack(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    pid_t targetPid = GetData<uint32_t>();
    mediaServerManager.DestroyStubObjectForPid(targetPid);
}

inline void MediaServerManagerFuzzer::CreateAndDestroyStub(MediaServerManager &mgr, MediaServerManager::StubType type)
{
    sptr<IRemoteObject> obj = mgr.CreateStubObject(type);
    if (obj != nullptr) {
        mgr.DestroyStubObject(type, obj);
    }
}

void MediaServerManagerFuzzer::FuzzReportAppMemoryUsage(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::PLAYER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::TRANSCODER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::RECORDERPROFILES);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::AVCODEC);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::SCREEN_CAPTURE);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::LPP_AUDIO_PLAYER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::LPP_VIDEO_PLAYER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::AVCODECLIST);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::AVMETADATAHELPER);
    CreateAndDestroyStub(mediaServerManager, MediaServerManager::StubType::RECORDER);

    uint32_t errType = 200;
    auto invalidType = static_cast<MediaServerManager::StubType>(errType);
    mediaServerManager.CreateStubObject(invalidType);
}

void MediaServerManagerFuzzer::FuzzGetPlayerPids(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.CreateStubObject(MediaServerManager::StubType::PLAYER);
    mediaServerManager.GetPlayerPids();
}

void MediaServerManagerFuzzer::FuzzDestroyDumperForPid(uint8_t *data, size_t size)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    pid_t targetPid = GetData<uint32_t>();
    mediaServerManager.DestroyDumperForPid(targetPid);
}

} // namespace Media

void FuzzTestMediaServerManager(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    MediaServerManagerFuzzer testMediaServerManager;
    return testMediaServerManager.FuzzMediaServerManagerAll(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestMediaServerManager(data, size);
    return 0;
}