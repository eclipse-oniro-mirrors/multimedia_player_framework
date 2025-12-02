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

#ifndef MEDIA_SERVER_MANAGER_H
#define MEDIA_SERVER_MANAGER_H

#include <memory>
#include <functional>
#include <map>
#include <list>
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "nocopyable.h"
#include "osal/task/task.h"
#include <set>
#include "lpp_capability.h"
namespace OHOS {
namespace Media {
using DumperEntry = std::function<int32_t(int32_t)>;

struct Dumper {
    pid_t pid_;
    pid_t uid_;
    time_t createInsTime_ {0};
    std::string insFakePointer_;
    DumperEntry entry_;
    sptr<IRemoteObject> remoteObject_;
};

class MediaServerManager : public NoCopyable {
public:
    static MediaServerManager &GetInstance();
    ~MediaServerManager();

    enum StubType {
        RECORDER = 0,
        PLAYER,
        AVMETADATAHELPER,
        AVCODECLIST,
        AVCODEC,
        RECORDERPROFILES,
        MONITOR,
        SCREEN_CAPTURE,
        SCREEN_CAPTURE_CONTROLLER,
        TRANSCODER,
        SCREEN_CAPTURE_MONITOR,
        LPP_AUDIO_PLAYER,
        LPP_VIDEO_PLAYER
    };
    sptr<IRemoteObject> CreateStubObject(StubType type);
    void DestroyStubObject(StubType type, sptr<IRemoteObject> object);
    void RemovePlayerStubFromMap(sptr<IRemoteObject> object, pid_t pid);
    void DestroyStubObjectForPid(pid_t pid);
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args);
    void DestroyDumper(StubType type, sptr<IRemoteObject> object);
    void DestroyDumperForPid(pid_t pid);
    void NotifyMemMgrLoaded();
    void DestoryMemoryReportTask();
    int32_t FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy);
    int32_t ResetAllProxy();
#ifdef SUPPORT_START_STOP_ON_DEMAND
    int32_t GetInstanceCount();
    int32_t GetInstanceCountLocked();
    int64_t GetCurrentSystemClockMs();
    int64_t GetAllInstancesReleasedTime();
    void ResetAllInstancesReleasedTime();
    void UpdateAllInstancesReleasedTime();
#endif
    bool CanKillMediaService();
    std::vector<pid_t> GetPlayerPids();
#ifdef SUPPORT_LPP_VIDEO_STRAMER
    int32_t GetLppCapacity(LppAvCapabilityInfo &lppAvCapability);
#endif

private:
    MediaServerManager();
#ifdef SUPPORT_PLAYER
    sptr<IRemoteObject> CreatePlayerStubObject();
#endif
#ifdef SUPPORT_RECORDER
    sptr<IRemoteObject> CreateRecorderStubObject();
    sptr<IRemoteObject> CreateRecorderProfilesStubObject();
#endif
#ifdef SUPPORT_TRANSCODER
    sptr<IRemoteObject> CreateTransCoderStubObject();
#endif
#ifdef SUPPORT_METADATA
    sptr<IRemoteObject> CreateAVMetadataHelperStubObject();
#endif
#ifdef SUPPORT_SCREEN_CAPTURE
    sptr<IRemoteObject> CreateScreenCaptureStubObject();
    sptr<IRemoteObject> CreateScreenCaptureMonitorStubObject();
    sptr<IRemoteObject> CreateScreenCaptureControllerStubObject();
#endif
#ifdef SUPPORT_LPP_AUDIO_STRAMER
    sptr<IRemoteObject> CreateLppAudioPlayerStubObject();
#endif
#ifdef SUPPORT_LPP_VIDEO_STRAMER
    sptr<IRemoteObject> CreateLppVideoPlayerStubObject();
#endif
    sptr<IRemoteObject> GetMonitorStubObject();
    sptr<IRemoteObject> CreateStubObjectByType(StubType type);

    void DestroyAVCodecStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyAVPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyAVRecorderStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyAVTransCoderStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyAVScreenCaptureStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyLppAudioPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyLppVideoPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid);
    void DestroyAVCodecStubForPid(pid_t pid);
    void DestroyAVPlayerStubForPid(pid_t pid);
    void DestroyAVRecorderStubForPid(pid_t pid);
    void DestroyAVTranscoderStubForPid(pid_t pid);
    void DestroyAVScreenCaptureStubForPid(pid_t pid);
    void DestroyLppAudioPlayerStubForPid(pid_t pid);
    void DestroyLppVideoPlayerStubForPid(pid_t pid);

    void StartMemoryReportTask();
    void ReleaseMemoryReportTask();
    bool GetMemUsageForPlayer();
    void ReportAppMemoryUsage();
    void SetCritical(bool critical);
    bool GetStubMapCountIsEmpty();
    std::atomic<bool> isMemMgrLoaded_ {false};

    class AsyncExecutor {
    public:
        AsyncExecutor() = default;
        virtual ~AsyncExecutor() = default;
        void Commit(sptr<IRemoteObject> obj);
        void Clear();
        void setClearCallBack(std::function<void()> callBack);
    private:
        void HandleAsyncExecution();
        std::list<sptr<IRemoteObject>> freeList_;
        std::mutex listMutex_;
        std::function<void()> callBack_;
    };
    std::map<sptr<IRemoteObject>, pid_t> recorderStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> transCoderStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> playerStubMap_;
    std::map<pid_t, std::set<sptr<IRemoteObject>>> pidToPlayerStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> avMetadataHelperStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> avCodecListStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> avCodecStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> recorderProfilesStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> screenCaptureStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> screenCaptureMonitorStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> screenCaptureControllerStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> lppAudioPlayerStubMap_;
    std::map<sptr<IRemoteObject>, pid_t> lppVideoPlayerStubMap_;
    std::map<StubType, std::vector<Dumper>> dumperTbl_;
    AsyncExecutor executor_;

    std::atomic<int32_t> needReleaseTaskCount_ = 0;
    std::mutex mutex_;
    std::unique_ptr<Task> memoryReportTask_{nullptr};
    std::unordered_map<pid_t, uint32_t> playerPidMem_{};
#ifdef SUPPORT_START_STOP_ON_DEMAND
    int64_t allInstancesReleasedTime_ {0};
#endif
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SERVER_MANAGER_H