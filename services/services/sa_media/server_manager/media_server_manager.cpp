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

#include "media_server_manager.h"
#include <unordered_set>
#include "media_utils.h"
#ifdef SUPPORT_RECORDER
#include "recorder_service_stub.h"
#include "recorder_profiles_service_stub.h"
#endif
#ifdef SUPPORT_TRANSCODER
#include "transcoder_service_stub.h"
#endif
#ifdef SUPPORT_PLAYER
#include "player_service_stub.h"
#ifdef PLAYER_USE_MEMORY_MANAGE
#include "player_service_stub_mem.h"
#endif
#endif
#ifdef SUPPORT_METADATA
#include "avmetadatahelper_service_stub.h"
#endif
#ifdef SUPPORT_SCREEN_CAPTURE
#include "screen_capture_service_stub.h"
#include "screen_capture_monitor_service_stub.h"
#include "screen_capture_controller_stub.h"
#endif
#ifdef SUPPORT_LPP_AUDIO_STRAMER
#include "lpp_audio_streamer_service_stub.h"
#endif
#ifdef SUPPORT_LPP_VIDEO_STRAMER
#include "lpp_video_streamer_service_stub.h"
#endif
#include "monitor_service_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "service_dump_manager.h"
#include "player_xcollie.h"
#include "client/memory_collector_client.h"
#include "system_ability_definition.h"
#include "mem_mgr_client.h"
#include <set>
#ifdef SUPPORT_LPP_VIDEO_STRAMER
#include "v1_0/ilow_power_player_factory.h"
namespace PlayerHDI = OHOS::HDI::LowPowerPlayer::V1_0;
#endif

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaServerManager"};
constexpr uint32_t REPORT_TIME = 100000000; // us
constexpr uint32_t MAX_TIMES = 5;
constexpr int32_t RELEASE_THRESHOLD = 3;  // relese task
}

namespace OHOS {
namespace Media {
constexpr uint32_t SERVER_MAX_NUMBER = 16;
MediaServerManager &MediaServerManager::GetInstance()
{
    static MediaServerManager instance;
    return instance;
}

void ConsoleInfo(std::map<pid_t, int32_t> &pidCount, std::string &dumpGroupInfoLog)
{
    for (const auto& pair : pidCount) {
        dumpGroupInfoLog += "-----#: ";
        dumpGroupInfoLog += "pid = " + std::to_string(pair.first) + ", insNum: ";
        dumpGroupInfoLog += std::to_string(pair.second) + "\n";
    }
    MEDIA_LOGI("%{public}s", dumpGroupInfoLog.c_str());
}

int32_t WriteInfo(int32_t fd, std::string &dumpString, std::vector<Dumper> dumpers, bool needDetail)
{
    int32_t i = 0;
    std::map<pid_t, int32_t> pidCount;
    std::string dumpGroupInfoLog = dumpString;
    for (auto iter : dumpers) {
        if (fd == -1) {
            if (pidCount.find(iter.pid_) != pidCount.end()) {
                pidCount[iter.pid_]++;
            } else {
                pidCount[iter.pid_] = 1;
            }
        }
        dumpString += "-----#" + std::to_string(i) + ": ";
        dumpString += "pid = ";
        dumpString += std::to_string(iter.pid_);
        if (iter.insFakePointer_.size() > 0) {
            dumpString += " ins = ";
            dumpString += iter.insFakePointer_;
        }
        if (iter.createInsTime_ > 0) {
            std::tm *pTm = std::localtime(&(iter.createInsTime_));
            if (pTm != nullptr) {
                dumpString += " time = ";
                dumpString += std::to_string(pTm->tm_mon + 1) + "-" + std::to_string(pTm->tm_mday) + " " +
                    std::to_string(pTm->tm_hour) + ":" + std::to_string(pTm->tm_min) + ":" +
                    std::to_string(pTm->tm_sec);
            }
        }
        dumpString += "-----\n";
        if (fd != -1) {
            write(fd, dumpString.c_str(), dumpString.size());
            dumpString.clear();
        }
        i++;
        if (needDetail && iter.entry_(fd) != MSERR_OK) {
            return OHOS::INVALID_OPERATION;
        }
    }
    if (fd != -1) {
        write(fd, dumpString.c_str(), dumpString.size());
    } else {
        MEDIA_LOGD("%{public}s", dumpString.c_str());
        ConsoleInfo(pidCount, dumpGroupInfoLog);
    }
    dumpString.clear();

    return OHOS::NO_ERROR;
}

int32_t MediaServerManager::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::string dumpString;
    std::unordered_set<std::u16string> argSets;
    for (decltype(args.size()) index = 0; index < args.size(); ++index) {
        argSets.insert(args[index]);
    }

    dumpString += "--PlayerServer--\n";
    auto ret = WriteInfo(fd, dumpString, dumperTbl_[StubType::PLAYER],
        argSets.find(u"player") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write PlayerServer information");

    dumpString += "--RecorderServer--\n";
    ret =  WriteInfo(fd, dumpString, dumperTbl_[StubType::RECORDER],
        argSets.find(u"recorder") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write RecorderServer information");

    dumpString += "--CodecServer--\n";
    ret = WriteInfo(fd, dumpString, dumperTbl_[StubType::AVCODEC],
        argSets.find(u"codec") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write CodecServer information");

    dumpString += "--AVMetaServer--\n";
    ret = WriteInfo(fd, dumpString, dumperTbl_[StubType::AVMETADATAHELPER], false);
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write AVMetaServer information");
    
    dumpString += "--TranscoderServer--\n";
    ret = WriteInfo(fd, dumpString, dumperTbl_[StubType::TRANSCODER],
        argSets.find(u"transcoder") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write Transcoder information");

    dumpString += "--ScreenCaptureServer--\n";
    ret = WriteInfo(fd, dumpString, dumperTbl_[StubType::SCREEN_CAPTURE],
        argSets.find(u"screencapture") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write ScreenCapture information");

    ret = ServiceDumpManager::GetInstance().Dump(fd, argSets);
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write dfx dump information");

    ret = PlayerXCollie::GetInstance().Dump(fd);
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write xcollie dump information");

    ret = MonitorServiceStub::GetInstance()->DumpInfo(fd,
        argSets.find(u"monitor") != argSets.end());
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to write monitor dump information");
    return OHOS::NO_ERROR;
}

MediaServerManager::MediaServerManager()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaServerManager::~MediaServerManager()
{
    std::unique_ptr<Task> memoryReportTask;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        memoryReportTask = std::move(memoryReportTask_);
    }
    if (memoryReportTask) {
        memoryReportTask->Stop();
    }
    playerPidMem_.clear();
    dumperTbl_.clear();
    recorderStubMap_.clear();
    playerStubMap_.clear();
    avMetadataHelperStubMap_.clear();
    avCodecListStubMap_.clear();
    avCodecStubMap_.clear();
    recorderProfilesStubMap_.clear();
    screenCaptureStubMap_.clear();
    screenCaptureMonitorStubMap_.clear();
    screenCaptureControllerStubMap_.clear();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t MediaServerManager::FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &pid : pidList) {
        auto pidIt = pidToPlayerStubMap_.find(pid);
        if (pidIt == pidToPlayerStubMap_.end()) {
            MEDIA_LOGD("PID(%{public}d) has no player stubs, skip freeze", pid);
            continue;
        }

        const auto &stubSet = pidIt->second;
        MEDIA_LOGI("Freezing %{public}zu player stubs for PID = %{public}d, isProxy: %{public}d",
                   stubSet.size(), pid, isProxy);
        
        for (const auto &stubObj : stubSet) {
            auto playerStub = iface_cast<PlayerServiceStub>(stubObj);
            CHECK_AND_CONTINUE_LOG(playerStub != nullptr,
                                   "failed to cast PlayerServiceStub, pid = %{public}d", pid);

            if (isProxy) {
                playerStub->Freeze();
            } else {
                playerStub->UnFreeze();
            }
        }
    }
    return MSERR_OK;
}

int32_t MediaServerManager::ResetAllProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("received ResetAllProxy");
    for (const auto &pidEntry : pidToPlayerStubMap_) {
        for (const auto &remoteObj : pidEntry.second) {
            auto playerStub = iface_cast<PlayerServiceStub>(remoteObj);
            CHECK_AND_CONTINUE_LOG(playerStub != nullptr,
                                   "failed to cast PlayerServiceStub, pid = %{public}d", pidEntry.first);
            playerStub->UnFreeze();
        }
    }
    return MSERR_OK;
}

sptr<IRemoteObject> MediaServerManager::CreateStubObject(StubType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool isEmpty = GetStubMapCountIsEmpty();

    auto res = CreateStubObjectByType(type);

    CHECK_AND_RETURN_RET_NOLOG((isEmpty && !GetStubMapCountIsEmpty()), res);
    SetCritical(true);
    return res;
}

sptr<IRemoteObject> MediaServerManager::CreateStubObjectByType(StubType type)
{
    switch (type) {
#ifdef SUPPORT_RECORDER
        case RECORDER:
            return CreateRecorderStubObject();
        case RECORDERPROFILES:
            return CreateRecorderProfilesStubObject();
#endif
#ifdef SUPPORT_TRANSCODER
        case TRANSCODER:
            return CreateTransCoderStubObject();
#endif
#ifdef SUPPORT_PLAYER
        case PLAYER:
            return CreatePlayerStubObject();
#endif
#ifdef SUPPORT_METADATA
        case AVMETADATAHELPER:
            return CreateAVMetadataHelperStubObject();
#endif
#ifdef SUPPORT_SCREEN_CAPTURE
        case SCREEN_CAPTURE:
            return CreateScreenCaptureStubObject();
        case SCREEN_CAPTURE_MONITOR:
            return CreateScreenCaptureMonitorStubObject();
        case SCREEN_CAPTURE_CONTROLLER:
            return CreateScreenCaptureControllerStubObject();
#endif
#ifdef SUPPORT_LPP_AUDIO_STRAMER
        case LPP_AUDIO_PLAYER:
            MEDIA_LOGI("LPP_AUDIO_PLAYER start");
            return CreateLppAudioPlayerStubObject();
#endif
#ifdef SUPPORT_LPP_VIDEO_STRAMER
        case LPP_VIDEO_PLAYER:
            MEDIA_LOGI("LPP_VIDEO_PLAYER start");
            return CreateLppVideoPlayerStubObject();
#endif
        case MONITOR:
            return GetMonitorStubObject();
        default:
            MEDIA_LOGE("default case, media server manager failed");
            return nullptr;
    }
}

#ifdef SUPPORT_PLAYER
sptr<IRemoteObject> MediaServerManager::CreatePlayerStubObject()
{
#ifdef PLAYER_USE_MEMORY_MANAGE
    sptr<PlayerServiceStub> playerStub;
    if (isMemMgrLoaded_.load()) {
        playerStub = PlayerServiceStubMem::Create();
    } else {
        MEDIA_LOGW("create player stub object when memmgr has not been loaded");
        playerStub = PlayerServiceStub::Create();
    }
#else
    sptr<PlayerServiceStub> playerStub = PlayerServiceStub::Create();
#endif
    CHECK_AND_RETURN_RET_LOG(playerStub != nullptr, nullptr, "failed to create PlayerServiceStub");
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    const uint8_t MAX_INSTANCE_LENGTH = 255;
    char text[MAX_INSTANCE_LENGTH];
    auto ret = sprintf_s(text, MAX_INSTANCE_LENGTH, "0x%06" PRIXPTR, FAKE_POINTER(playerStub.GetRefPtr()));
    std::string InsPointerStr = "";
    if (ret > 0) {
        InsPointerStr.assign(text, ret);
    }

    sptr<IRemoteObject> object = playerStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create PlayerServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    playerStubMap_[object] = pid;

    StartMemoryReportTask();

    auto &instanceSet = pidToPlayerStubMap_[pid];
    instanceSet.insert(object);

    Dumper dumper;
    dumper.entry_ = [player = playerStub](int32_t fd) -> int32_t {
        return player->DumpInfo(fd);
    };
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.createInsTime_ = now;
    dumper.insFakePointer_ = InsPointerStr;
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::PLAYER].emplace_back(dumper);
    MEDIA_LOGD("The number of player services(%{public}zu) pid(%{public}d).",
        playerStubMap_.size(), pid);
    MediaTrace::CounterTrace("The number of player", playerStubMap_.size());
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}
#endif

#ifdef SUPPORT_RECORDER
sptr<IRemoteObject> MediaServerManager::CreateRecorderStubObject()
{
    sptr<RecorderServiceStub> recorderStub = RecorderServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(recorderStub != nullptr, nullptr, "failed to create RecorderServiceStub");

    sptr<IRemoteObject> object = recorderStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create RecorderServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    recorderStubMap_[object] = pid;

    Dumper dumper;
    dumper.entry_ = [recorder = recorderStub](int32_t fd) -> int32_t {
        return recorder->DumpInfo(fd);
    };
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::RECORDER].emplace_back(dumper);
    MEDIA_LOGD("The number of recorder services(%{public}zu) pid(%{public}d).",
        recorderStubMap_.size(), pid);
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}

sptr<IRemoteObject> MediaServerManager::CreateRecorderProfilesStubObject()
{
    CHECK_AND_RETURN_RET_LOG(recorderProfilesStubMap_.size() < SERVER_MAX_NUMBER,
        nullptr, "The number of recorder_profiles services(%{public}zu) has reached the upper limit."
        "Please release the applied resources.", recorderProfilesStubMap_.size());

    sptr<RecorderProfilesServiceStub> recorderProfilesStub = RecorderProfilesServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(recorderProfilesStub != nullptr, nullptr,
        "failed to create recorderProfilesStub");

    sptr<IRemoteObject> object = recorderProfilesStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create recorderProfilesStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    recorderProfilesStubMap_[object] = pid;
    MEDIA_LOGD("The number of recorder_profiles services(%{public}zu).", recorderProfilesStubMap_.size());
    return object;
}
#endif

#ifdef SUPPORT_TRANSCODER
sptr<IRemoteObject> MediaServerManager::CreateTransCoderStubObject()
{
    sptr<TransCoderServiceStub> transCoderStub = TransCoderServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(transCoderStub != nullptr, nullptr, "failed to create TransCoderServiceStub");
 
    sptr<IRemoteObject> object = transCoderStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create TransCoderServiceStub");
 
    pid_t pid = IPCSkeleton::GetCallingPid();
    transCoderStubMap_[object] = pid;
 
    Dumper dumper;
    dumper.entry_ = [transCoder = transCoderStub](int32_t fd) -> int32_t {
        return transCoder->DumpInfo(fd);
    };
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::TRANSCODER].emplace_back(dumper);
    MEDIA_LOGD("The number of transCoder services(%{public}zu) pid(%{public}d).",
        transCoderStubMap_.size(), pid);
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}
#endif

#ifdef SUPPORT_METADATA
sptr<IRemoteObject> MediaServerManager::CreateAVMetadataHelperStubObject()
{
    sptr<AVMetadataHelperServiceStub> avMetadataHelperStub = AVMetadataHelperServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperStub != nullptr, nullptr,
        "failed to create AVMetadataHelperServiceStub");

    sptr<IRemoteObject> object = avMetadataHelperStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr,
        "failed to create AVMetadataHelperServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    avMetadataHelperStubMap_[object] = pid;

    Dumper dumper;
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::AVMETADATAHELPER].emplace_back(dumper);

    MEDIA_LOGD("The number of avmetadatahelper services(%{public}zu) pid(%{public}d).",
        avMetadataHelperStubMap_.size(), pid);
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}
#endif

#ifdef SUPPORT_SCREEN_CAPTURE
sptr<IRemoteObject> MediaServerManager::CreateScreenCaptureStubObject()
{
    sptr<ScreenCaptureServiceStub> screenCaptureStub = ScreenCaptureServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(screenCaptureStub != nullptr, nullptr,
        "failed to create ScreenCaptureServiceStub");

    sptr<IRemoteObject> object = screenCaptureStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create ScreenCaptureServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    screenCaptureStubMap_[object] = pid;

    Dumper dumper;
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::SCREEN_CAPTURE].emplace_back(dumper);
    MEDIA_LOGD("The number of screen capture services(%{public}zu).", screenCaptureStubMap_.size());
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}

sptr<IRemoteObject> MediaServerManager::CreateScreenCaptureMonitorStubObject()
{
    sptr<ScreenCaptureMonitorServiceStub> screenCaptureMonitorStub = ScreenCaptureMonitorServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(screenCaptureMonitorStub != nullptr, nullptr,
        "failed to create ScreenCaptureMonitorServiceStub");

    sptr<IRemoteObject> object = screenCaptureMonitorStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create ScreenCaptureMonitorServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    screenCaptureMonitorStubMap_[object] = pid;

    Dumper dumper;
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::SCREEN_CAPTURE_MONITOR].emplace_back(dumper);
    MEDIA_LOGD("The number of screen capture monitor services(%{public}zu).", screenCaptureMonitorStubMap_.size());
    (void)Dump(-1, std::vector<std::u16string>());
    return object;
}

sptr<IRemoteObject> MediaServerManager::CreateScreenCaptureControllerStubObject()
{
    sptr<ScreenCaptureControllerStub> screenCaptureControllerStub = ScreenCaptureControllerStub::Create();
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerStub != nullptr, nullptr,
        "failed to create ScreenCaptureControllerStub");

    sptr<IRemoteObject> object = screenCaptureControllerStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to create screenCaptureControllerStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    screenCaptureControllerStubMap_[object] = pid;
    MEDIA_LOGD("The number of screen capture services(%{public}zu).", screenCaptureControllerStubMap_.size());
    MEDIA_LOGI("MediaServerManager::CreateScreenCaptureControllerStubObject() end");
    return object;
}
#endif

#ifdef SUPPORT_LPP_AUDIO_STRAMER
sptr<IRemoteObject> MediaServerManager::CreateLppAudioPlayerStubObject()
{
    MEDIA_LOGI("CreateLppAudioPlayerStubObject start");
    sptr<LppAudioStreamerServiceStub> lppAudioPlayerStub = LppAudioStreamerServiceStub::Create();
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerStub != nullptr, nullptr,
        "failed to create LppAudioStreamerServiceStub");
 
    sptr<IRemoteObject> object = lppAudioPlayerStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr,
        "failed to create LppAudioStreamerServiceStub");
 
    pid_t pid = IPCSkeleton::GetCallingPid();
    lppAudioPlayerStubMap_[object] = pid;
 
    Dumper dumper;
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::LPP_AUDIO_PLAYER].emplace_back(dumper);
 
    MEDIA_LOGD("The number of lppaudio player services(%{public}zu) pid(%{public}d).",
        lppAudioPlayerStubMap_.size(), pid);
    (void)Dump(-1, std::vector<std::u16string>());
    MEDIA_LOGI("CreateLppAudioPlayerStubObject end");
    return object;
}
#endif
 
#ifdef SUPPORT_LPP_VIDEO_STRAMER
int32_t MediaServerManager::GetLppCapacity(LppAvCapabilityInfo &lppAvCapability)
{
    auto factory = PlayerHDI::ILowPowerPlayerFactory::Get(true);
    CHECK_AND_RETURN_RET_LOG(factory != nullptr, UNKNOWN_ERROR, "MediaServerManager::GetLppCapacity is failed");
    PlayerHDI::LppAVCap lppAVCap;
    int32_t ret = factory->GetAVCapability(lppAVCap);
    MEDIA_LOGI("MediaServerManager::GetLppCapacity %{public}lu %{public}lu",
        lppAVCap.videoCap.size(), lppAVCap.audioCap.size());
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "FAILED MediaServerManager::GetLppCapacity");
    lppAvCapability.SetLppAvCapabilityInfo(lppAVCap);
    return ret;
}

sptr<IRemoteObject> MediaServerManager::CreateLppVideoPlayerStubObject()
{
    MEDIA_LOGI("CreateLppVideoPlayerStubObject start");
    sptr<LppVideoStreamerServiceStub> lppVideoPlayerStub = LppVideoStreamerServiceStub::Create();
    
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerStub != nullptr, nullptr,
        "failed to create LppVideoStreamerServiceStub");

    sptr<IRemoteObject> object = lppVideoPlayerStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr,
        "failed to create LppVideoStreamerServiceStub");

    pid_t pid = IPCSkeleton::GetCallingPid();
    lppVideoPlayerStubMap_[object] = pid;

    Dumper dumper;
    dumper.pid_ = pid;
    dumper.uid_ = IPCSkeleton::GetCallingUid();
    dumper.remoteObject_ = object;
    dumperTbl_[StubType::LPP_VIDEO_PLAYER].emplace_back(dumper);

    MEDIA_LOGD("The number of lppvideo player services(%{public}zu) pid(%{public}d).",
        lppVideoPlayerStubMap_.size(), pid);
    (void)Dump(-1, std::vector<std::u16string>());
    MEDIA_LOGI("CreateLppVideoPlayerStubObject end");
    return object;
}
#endif

sptr<IRemoteObject> MediaServerManager::GetMonitorStubObject()
{
    sptr<MonitorServiceStub> monitorStub = MonitorServiceStub::GetInstance();
    CHECK_AND_RETURN_RET_LOG(monitorStub != nullptr, nullptr, "failed to create MonitorServiceStub");
    sptr<IRemoteObject> object = monitorStub->AsObject();
    return object;
}

void MediaServerManager::DestroyAVCodecStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case AVCODEC: {
            for (auto it = avCodecStubMap_.begin(); it != avCodecStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy avcodec stub services(%{public}zu) pid(%{public}d).",
                        avCodecStubMap_.size(), pid);
                    (void)avCodecStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find avcodec object failed, pid(%{public}d).", pid);
            break;
        }
        case AVCODECLIST: {
            for (auto it = avCodecListStubMap_.begin(); it != avCodecListStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy avcodeclist stub services(%{public}zu) pid(%{public}d).",
                        avCodecListStubMap_.size(), pid);
                    (void)avCodecListStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find avcodeclist object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::DestroyAVTransCoderStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case TRANSCODER: {
            for (auto it = transCoderStubMap_.begin(); it != transCoderStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy transCoder stub services(%{public}zu) pid(%{public}d).",
                        transCoderStubMap_.size(), pid);
                    (void)transCoderStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find transCoder object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::DestroyAVPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case PLAYER: {
            for (auto it = playerStubMap_.begin(); it != playerStubMap_.end(); it++) {
                CHECK_AND_CONTINUE(it->first == object);
                RemovePlayerStubFromMap(object, it->second);
                MEDIA_LOGD("destroy player stub services(%{public}zu) pid(%{public}d).",
                    playerStubMap_.size(), pid);
                (void)playerStubMap_.erase(it);
                MediaTrace::CounterTrace("The number of player", playerStubMap_.size());
                return;
            }
            MEDIA_LOGE("find player object failed, pid(%{public}d).", pid);
            break;
        }
        case AVMETADATAHELPER: {
            for (auto it = avMetadataHelperStubMap_.begin(); it != avMetadataHelperStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy avmetadatahelper stub services(%{public}zu) pid(%{public}d).",
                        avMetadataHelperStubMap_.size(), pid);
                    (void)avMetadataHelperStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find avmetadatahelper object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::RemovePlayerStubFromMap(sptr<IRemoteObject> object, pid_t pid)
{
    auto pidIt = pidToPlayerStubMap_.find(pid);
    if (pidIt == pidToPlayerStubMap_.end()) {
        return;
    }

    pidIt->second.erase(object);
    if (pidIt->second.empty()) {
        pidToPlayerStubMap_.erase(pidIt);
    }
}

void MediaServerManager::DestroyAVRecorderStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case RECORDER: {
            for (auto it = recorderStubMap_.begin(); it != recorderStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy recorder stub services(%{public}zu) pid(%{public}d).",
                        recorderStubMap_.size(), pid);
                    (void)recorderStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find recorder object failed, pid(%{public}d).", pid);
            break;
        }
        case RECORDERPROFILES: {
            for (auto it = recorderProfilesStubMap_.begin(); it != recorderProfilesStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy mediaprofile stub services(%{public}zu) pid(%{public}d).",
                        recorderProfilesStubMap_.size(), pid);
                    (void)recorderProfilesStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find mediaprofile object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::DestroyAVScreenCaptureStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case SCREEN_CAPTURE: {
            for (auto it = screenCaptureStubMap_.begin(); it != screenCaptureStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy screen capture stub services(%{public}zu) pid(%{public}d).",
                        screenCaptureStubMap_.size(), pid);
                    (void)screenCaptureStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find screen capture object failed, pid(%{public}d).", pid);
            break;
        }
        case SCREEN_CAPTURE_MONITOR: {
            for (auto it = screenCaptureMonitorStubMap_.begin(); it != screenCaptureMonitorStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy screen capture monitor stub services(%{public}zu) pid(%{public}d).",
                        screenCaptureMonitorStubMap_.size(), pid);
                    (void)screenCaptureMonitorStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find screen capture monitor object failed, pid(%{public}d).", pid);
            break;
        }
        case SCREEN_CAPTURE_CONTROLLER: {
            for (auto it = screenCaptureControllerStubMap_.begin();
                it != screenCaptureControllerStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy screen capture controller stub services(%{public}zu) pid(%{public}d).",
                        screenCaptureControllerStubMap_.size(), pid);
                    (void)screenCaptureControllerStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find screen capture controller object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::DestroyLppAudioPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case LPP_AUDIO_PLAYER: {
            for (auto it = lppAudioPlayerStubMap_.begin(); it != lppAudioPlayerStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy lppaudio player stub services(%{public}zu) pid(%{public}d).",
                        lppAudioPlayerStubMap_.size(), pid);
                    (void)lppAudioPlayerStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find lppaudio player object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}
 
void MediaServerManager::DestroyLppVideoPlayerStub(StubType type, sptr<IRemoteObject> object, pid_t pid)
{
    switch (type) {
        case LPP_VIDEO_PLAYER: {
            for (auto it = lppVideoPlayerStubMap_.begin(); it != lppVideoPlayerStubMap_.end(); it++) {
                if (it->first == object) {
                    MEDIA_LOGD("destroy lppvideo player stub services(%{public}zu) pid(%{public}d).",
                        lppVideoPlayerStubMap_.size(), pid);
                    (void)lppVideoPlayerStubMap_.erase(it);
                    return;
                }
            }
            MEDIA_LOGE("find lppvideo player object failed, pid(%{public}d).", pid);
            break;
        }
        default:
            break;
    }
}

void MediaServerManager::DestroyStubObject(StubType type, sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pid_t pid = IPCSkeleton::GetCallingPid();
    DestroyDumper(type, object);
    switch (type) {
        case TRANSCODER:
            DestroyAVTransCoderStub(type, object, pid);
            break;
        case RECORDER:
        case RECORDERPROFILES:
            DestroyAVRecorderStub(type, object, pid);
            break;
        case PLAYER:
        case AVMETADATAHELPER:
            DestroyAVPlayerStub(type, object, pid);
            break;
        case AVCODEC:
        case AVCODECLIST:
            DestroyAVCodecStub(type, object, pid);
            break;
        case SCREEN_CAPTURE:
        case SCREEN_CAPTURE_MONITOR:
        case SCREEN_CAPTURE_CONTROLLER:
            DestroyAVScreenCaptureStub(type, object, pid);
            break;
        case LPP_AUDIO_PLAYER:
            DestroyLppAudioPlayerStub(type, object, pid);
            break;
        case LPP_VIDEO_PLAYER:
            DestroyLppVideoPlayerStub(type, object, pid);
            break;
        default: {
            MEDIA_LOGE("default case, media server manager failed, pid(%{public}d).", pid);
            break;
        }
    }
#ifdef SUPPORT_START_STOP_ON_DEMAND
    UpdateAllInstancesReleasedTime();
#endif
    CHECK_AND_RETURN_NOLOG(GetStubMapCountIsEmpty());
    SetCritical(false);
}

void MediaServerManager::DestroyAVScreenCaptureStubForPid(pid_t pid)
{
    MEDIA_LOGD("ScreenCapture stub services(%{public}zu) pid(%{public}d).", screenCaptureStubMap_.size(), pid);
    for (auto itScreenCapture = screenCaptureStubMap_.begin(); itScreenCapture != screenCaptureStubMap_.end();) {
        if (itScreenCapture->second == pid) {
            executor_.Commit(itScreenCapture->first);
            itScreenCapture = screenCaptureStubMap_.erase(itScreenCapture);
        } else {
            itScreenCapture++;
        }
    }
    MEDIA_LOGD("ScreenCapture stub services(%{public}zu).", screenCaptureStubMap_.size());
    MEDIA_LOGD("ScreenCapture monitor stub services(%{public}zu) pid(%{public}d).",
        screenCaptureMonitorStubMap_.size(), pid);
    for (auto itScreenCaptureMonitor = screenCaptureMonitorStubMap_.begin();
         itScreenCaptureMonitor != screenCaptureMonitorStubMap_.end();) {
        if (itScreenCaptureMonitor->second == pid) {
            executor_.Commit(itScreenCaptureMonitor->first);
            itScreenCaptureMonitor = screenCaptureMonitorStubMap_.erase(itScreenCaptureMonitor);
        } else {
            itScreenCaptureMonitor++;
        }
    }
    MEDIA_LOGD("ScreenCapture monitor stub services(%{public}zu).", screenCaptureMonitorStubMap_.size());
    MEDIA_LOGD("ScreenCapture controller stub services(%{public}zu) pid(%{public}d).",
        screenCaptureControllerStubMap_.size(), pid);
    for (auto itScreenCaptureController = screenCaptureControllerStubMap_.begin();
         itScreenCaptureController != screenCaptureControllerStubMap_.end();) {
        if (itScreenCaptureController->second == pid) {
            executor_.Commit(itScreenCaptureController->first);
            itScreenCaptureController = screenCaptureControllerStubMap_.erase(itScreenCaptureController);
        } else {
            itScreenCaptureController++;
        }
    }
    MEDIA_LOGD("ScreenCapture controller stub services(%{public}zu).", screenCaptureControllerStubMap_.size());
}

void MediaServerManager::DestroyAVTranscoderStubForPid(pid_t pid)
{
    MEDIA_LOGD("AVTranscoder stub services(%{public}zu) pid(%{public}d).", transCoderStubMap_.size(), pid);
    for (auto itTranscoder = transCoderStubMap_.begin(); itTranscoder != transCoderStubMap_.end();) {
        if (itTranscoder->second == pid) {
            executor_.Commit(itTranscoder->first);
            itTranscoder = transCoderStubMap_.erase(itTranscoder);
        } else {
            itTranscoder++;
        }
    }
    MEDIA_LOGD("AVTranscoder stub services(%{public}zu).", transCoderStubMap_.size());
}

void MediaServerManager::DestroyAVCodecStubForPid(pid_t pid)
{
    MEDIA_LOGD("avcodec stub services(%{public}zu) pid(%{public}d).", avCodecStubMap_.size(), pid);
    for (auto itAvCodec = avCodecStubMap_.begin(); itAvCodec != avCodecStubMap_.end();) {
        if (itAvCodec->second == pid) {
            executor_.Commit(itAvCodec->first);
            itAvCodec = avCodecStubMap_.erase(itAvCodec);
        } else {
            itAvCodec++;
        }
    }
    MEDIA_LOGD("avcodec stub services(%{public}zu).", avCodecStubMap_.size());

    MEDIA_LOGD("avcodeclist stub services(%{public}zu) pid(%{public}d).", avCodecListStubMap_.size(), pid);
    for (auto itAvCodecList = avCodecListStubMap_.begin(); itAvCodecList != avCodecListStubMap_.end();) {
        if (itAvCodecList->second == pid) {
            executor_.Commit(itAvCodecList->first);
            itAvCodecList = avCodecListStubMap_.erase(itAvCodecList);
        } else {
            itAvCodecList++;
        }
    }
    MEDIA_LOGD("avcodeclist stub services(%{public}zu).", avCodecListStubMap_.size());
}

void MediaServerManager::DestroyAVPlayerStubForPid(pid_t pid)
{
    MEDIA_LOGD("player stub services(%{public}zu) pid(%{public}d).", playerStubMap_.size(), pid);
    auto pidIt = pidToPlayerStubMap_.find(pid);
    if (pidIt != pidToPlayerStubMap_.end()) {
        pidToPlayerStubMap_.erase(pidIt);
    }
    for (auto itPlayer = playerStubMap_.begin(); itPlayer != playerStubMap_.end();) {
        if (itPlayer->second == pid) {
            executor_.Commit(itPlayer->first);
            itPlayer = playerStubMap_.erase(itPlayer);
        } else {
            itPlayer++;
        }
    }
    MEDIA_LOGD("player stub services(%{public}zu).", playerStubMap_.size());

    MEDIA_LOGD("avmetadatahelper stub services(%{public}zu) pid(%{public}d).", avMetadataHelperStubMap_.size(), pid);
    for (auto itAvMetadata = avMetadataHelperStubMap_.begin(); itAvMetadata != avMetadataHelperStubMap_.end();) {
        if (itAvMetadata->second == pid) {
            executor_.Commit(itAvMetadata->first);
            itAvMetadata = avMetadataHelperStubMap_.erase(itAvMetadata);
        } else {
            itAvMetadata++;
        }
    }
    MEDIA_LOGD("avmetadatahelper stub services(%{public}zu).", avMetadataHelperStubMap_.size());
}

void MediaServerManager::DestroyAVRecorderStubForPid(pid_t pid)
{
    MEDIA_LOGD("recorder stub services(%{public}zu) pid(%{public}d).", recorderStubMap_.size(), pid);
    for (auto itRecorder = recorderStubMap_.begin(); itRecorder != recorderStubMap_.end();) {
        if (itRecorder->second == pid) {
            executor_.Commit(itRecorder->first);
            itRecorder = recorderStubMap_.erase(itRecorder);
        } else {
            itRecorder++;
        }
    }
    MEDIA_LOGD("recorder stub services(%{public}zu).", recorderStubMap_.size());

    MEDIA_LOGD("mediaprofile stub services(%{public}zu) pid(%{public}d).", recorderProfilesStubMap_.size(), pid);
    for (auto itMediaProfile = recorderProfilesStubMap_.begin(); itMediaProfile != recorderProfilesStubMap_.end();) {
        if (itMediaProfile->second == pid) {
            executor_.Commit(itMediaProfile->first);
            itMediaProfile = recorderProfilesStubMap_.erase(itMediaProfile);
        } else {
            itMediaProfile++;
        }
    }
    MEDIA_LOGD("mediaprofile stub services(%{public}zu).", recorderProfilesStubMap_.size());
}

void MediaServerManager::DestroyLppAudioPlayerStubForPid(pid_t pid)
{
    MEDIA_LOGD("LppAudioPlayer stub services(%{public}zu) pid(%{public}d).", lppAudioPlayerStubMap_.size(), pid);
    for (auto itLppAudioPlayer = lppAudioPlayerStubMap_.begin(); itLppAudioPlayer != lppAudioPlayerStubMap_.end();) {
        if (itLppAudioPlayer->second == pid) {
            executor_.Commit(itLppAudioPlayer->first);
            itLppAudioPlayer = lppAudioPlayerStubMap_.erase(itLppAudioPlayer);
        } else {
            itLppAudioPlayer++;
        }
    }
    MEDIA_LOGD("LppAudioPlayer stub services(%{public}zu).", lppAudioPlayerStubMap_.size());
}
 
void MediaServerManager::DestroyLppVideoPlayerStubForPid(pid_t pid)
{
    MEDIA_LOGD("LppVideoPlayer stub services(%{public}zu) pid(%{public}d).", lppVideoPlayerStubMap_.size(), pid);
    for (auto itLppVideoPlayer = lppVideoPlayerStubMap_.begin(); itLppVideoPlayer != lppVideoPlayerStubMap_.end();) {
        if (itLppVideoPlayer->second == pid) {
            executor_.Commit(itLppVideoPlayer->first);
            itLppVideoPlayer = lppVideoPlayerStubMap_.erase(itLppVideoPlayer);
        } else {
            itLppVideoPlayer++;
        }
    }
    MEDIA_LOGD("LppVideoPlayer stub services(%{public}zu).", lppVideoPlayerStubMap_.size());
}

void MediaServerManager::DestroyStubObjectForPid(pid_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DestroyDumperForPid(pid);
    DestroyAVRecorderStubForPid(pid);
    DestroyAVPlayerStubForPid(pid);
    DestroyAVCodecStubForPid(pid);
    DestroyAVTranscoderStubForPid(pid);
    DestroyAVScreenCaptureStubForPid(pid);
    DestroyLppAudioPlayerStubForPid(pid);
    DestroyLppVideoPlayerStubForPid(pid);
    MonitorServiceStub::GetInstance()->OnClientDie(pid);
    executor_.SetClearCallBack([this]() {
        CHECK_AND_RETURN_NOLOG(GetStubMapCountIsEmpty());
        SetCritical(false);
    });
    executor_.Clear();
#ifdef SUPPORT_START_STOP_ON_DEMAND
    UpdateAllInstancesReleasedTime();
#endif
}

std::vector<pid_t> MediaServerManager::GetPlayerPids()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<pid_t> res;
    CHECK_AND_RETURN_RET_NOLOG(!playerStubMap_.empty(), res);
    std::unordered_set<pid_t> tmpRes;
    for (const auto& [object, pid] : playerStubMap_) {
        (void)tmpRes.insert(pid);
    }
    for (auto &uniqPid : tmpRes) {
        res.emplace_back(uniqPid);
    }
    return res;
}

void MediaServerManager::DestroyDumper(StubType type, sptr<IRemoteObject> object)
{
    for (auto it = dumperTbl_[type].begin(); it != dumperTbl_[type].end(); it++) {
        if (it->remoteObject_ == object) {
            (void)dumperTbl_[type].erase(it);
            MEDIA_LOGD("MediaServerManager::DestroyDumper");
            (void)Dump(-1, std::vector<std::u16string>());
            return;
        }
    }
}

void MediaServerManager::DestroyDumperForPid(pid_t pid)
{
    for (auto &dumpers : dumperTbl_) {
        for (auto it = dumpers.second.begin(); it != dumpers.second.end();) {
            if (it->pid_ == pid) {
                it = dumpers.second.erase(it);
                MEDIA_LOGD("MediaServerManager::DestroyDumperForPid");
            } else {
                it++;
            }
        }
    }
    (void)Dump(-1, std::vector<std::u16string>());
}

void MediaServerManager::StartMemoryReportTask()
{
    MediaTrace trace("MediaServerManager::StartMemoryReport");
    if (memoryReportTask_ == nullptr) {
        memoryReportTask_ = std::make_unique<Task>("playerMemReport", "",
            TaskType::SINGLETON, TaskPriority::NORMAL, true);
        memoryReportTask_->RegisterJob([this] {
            this->ReportAppMemoryUsage();
            return REPORT_TIME;
        });
        needReleaseTaskCount_ = 0;
    }
    if (memoryReportTask_ && !memoryReportTask_->IsTaskRunning()) {
        memoryReportTask_->Start();
    }
}

bool MediaServerManager::GetMemUsageForPlayer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<pid_t, uint32_t> memoryList;
    for (const auto& [object, pid] : playerStubMap_) {
        auto stub = iface_cast<PlayerServiceStub>(object);
        auto num = stub->GetMemoryUsage();
        if (num == 0) {
            continue;
        }
        memoryList[pid] += num;
    }

    for (const auto &[pid, mem] : playerPidMem_) {
        if (memoryList.find(pid) == memoryList.end() && mem != 0) {
            memoryList[pid] = 0;
        }
    }
    playerPidMem_.swap(memoryList);
    if (playerPidMem_.empty()) {
        needReleaseTaskCount_.fetch_add(1, std::memory_order_relaxed);
        if (needReleaseTaskCount_ >= RELEASE_THRESHOLD) {
            std::thread([memoryReportTask = std::move(memoryReportTask_)]() mutable -> void {
                MEDIA_LOGI("memoryReportTask: release");
            }).detach();
        }
        return false;
    }
    needReleaseTaskCount_ = 0;
    return true;
}

void MediaServerManager::ReportAppMemoryUsage()
{
    CHECK_AND_RETURN_LOG(GetMemUsageForPlayer(), "no need report");
    auto memoryCollector = HiviewDFX::UCollectClient::MemoryCollector::Create();
    CHECK_AND_RETURN_LOG(memoryCollector != nullptr, "Create Hiview DFX memory collector failed");

    std::vector<HiviewDFX::UCollectClient::MemoryCaller> memList;
    memList.reserve(playerPidMem_.size());

    for (auto &[pid, mem] : playerPidMem_) {
        MEDIA_LOGI("memory usage pid(%{public}d) mem(%{public}d KB).", pid, static_cast<int32_t>(mem));
        HiviewDFX::UCollectClient::MemoryCaller memoryCaller = {
            .pid = pid,
            .resourceType = "media_service",
            .limitValue = mem,
        };
        memList.emplace_back(memoryCaller);
    }
    memoryCollector->SetSplitMemoryValue(memList);
}

void MediaServerManager::SetCritical(bool critical)
{
    CHECK_AND_RETURN_LOG(GetClientBundleName(IPCSkeleton::GetCallingUid()) != "bootanimation",
        "MediaServerManager::SetCritical do not SetCritical");
    auto ret = Memory::MemMgrClient::GetInstance().SetCritical(getpid(), critical, PLAYER_DISTRIBUTED_SERVICE_ID);
    CHECK_AND_RETURN_LOG(ret == 0, "MediaServerManager::SetCritical set critical to %{public}d fail.", critical);
    MEDIA_LOGI("MediaServerManager::SetCritical set critical to %{public}d success.", critical);
}

bool MediaServerManager::GetStubMapCountIsEmpty()
{
    return recorderStubMap_.empty() && transCoderStubMap_.empty() && playerStubMap_.empty() &&
            pidToPlayerStubMap_.empty() && avMetadataHelperStubMap_.empty() && avCodecListStubMap_.empty() &&
            avCodecStubMap_.empty() && recorderProfilesStubMap_.empty() &&
            screenCaptureStubMap_.empty() && screenCaptureControllerStubMap_.empty() &&
            lppAudioPlayerStubMap_.empty() && lppVideoPlayerStubMap_.empty();
}

void MediaServerManager::NotifyMemMgrLoaded()
{
    isMemMgrLoaded_.store(true);
}

void MediaServerManager::DestoryMemoryReportTask()
{
    MediaTrace trace("MediaServerManager::DestoryMemoryReportTask");
    MEDIA_LOGI("DestoryMemoryReportTask");
    std::unique_ptr<Task> memoryReportTask{nullptr};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        memoryReportTask = std::move(memoryReportTask_);
        if (memoryReportTask && memoryReportTask->IsTaskRunning()) {
            memoryReportTask->StopAsync();
        }
    }
}

void MediaServerManager::AsyncExecutor::Commit(sptr<IRemoteObject> obj)
{
    std::lock_guard<std::mutex> lock(listMutex_);
    freeList_.push_back(obj);
}

void MediaServerManager::AsyncExecutor::Clear()
{
    std::thread(&MediaServerManager::AsyncExecutor::HandleAsyncExecution, this).detach();
}

void MediaServerManager::AsyncExecutor::HandleAsyncExecution()
{
    std::list<sptr<IRemoteObject>> tempList;
    {
        std::lock_guard<std::mutex> lock(listMutex_);
        freeList_.swap(tempList);
    }
    int32_t times = 0;
    while (times < MAX_TIMES) {
        bool allStubsRefCountLessOrEqual1 = false;
        for (auto& item : tempList) {
            int refCount = item->GetSptrRefCount();
            allStubsRefCountLessOrEqual1 = refCount > 1;
        }
        CHECK_AND_BREAK(allStubsRefCountLessOrEqual1);
        sleep(1);
        times++;
    }
    tempList.clear();
    callBack_();
}

void MediaServerManager::AsyncExecutor::SetClearCallBack(std::function<void()> callBack)
{
    std::lock_guard<std::mutex> lock(listMutex_);
    callBack_ = callBack;
}

#ifdef SUPPORT_START_STOP_ON_DEMAND
int32_t MediaServerManager::GetInstanceCountLocked()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return GetInstanceCount();
}

int32_t MediaServerManager::GetInstanceCount()
{
    return static_cast<int32_t>(recorderStubMap_.size() + playerStubMap_.size() + avMetadataHelperStubMap_.size() +
           avCodecListStubMap_.size() + avCodecStubMap_.size() + recorderProfilesStubMap_.size() +
           screenCaptureStubMap_.size() + screenCaptureControllerStubMap_.size() +
           screenCaptureMonitorStubMap_.size() + transCoderStubMap_.size());
}

int64_t MediaServerManager::GetCurrentSystemClockMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int64_t MediaServerManager::GetAllInstancesReleasedTime()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return allInstancesReleasedTime_;
}

void MediaServerManager::ResetAllInstancesReleasedTime()
{
    std::lock_guard<std::mutex> lock(mutex_);
    allInstancesReleasedTime_ = 0;
}

void MediaServerManager::UpdateAllInstancesReleasedTime()
{
    if (allInstancesReleasedTime_ == 0 && GetInstanceCount() == 0) {
        allInstancesReleasedTime_ = GetCurrentSystemClockMs();
    }
}
#endif

bool MediaServerManager::CanKillMediaService()
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool canKillMediaService = !recorderStubMap_.empty() ||
                     !avMetadataHelperStubMap_.empty() ||
                     !screenCaptureStubMap_.empty() ||
                     !recorderProfilesStubMap_.empty() ||
                     !screenCaptureControllerStubMap_.empty() ||
                     !transCoderStubMap_.empty();
    return !canKillMediaService;
}
} // namespace Media
} // namespace OHOS
