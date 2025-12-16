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

#include "avmetadatahelper_server.h"
#include "media_log.h"
#include "media_errors.h"
#include "engine_factory_repo.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "media_utils.h"
#include "ipc_skeleton.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "MetaHelperServer"};
}

namespace OHOS {
namespace Media {
static const std::unordered_map<int32_t, std::string> STATUS_TO_STATUS_DESCRIPTION_TABLE = {
    {HELPER_STATE_ERROR, "HELPER_STATE_ERROR"},
    {HELPER_IDLE, "HELPER_IDLE"},
    {HELPER_PREPARED, "HELPER_PREPARED"},
    {HELPER_CALL_DONE, "HELPER_CALL_DONE"},
    {HELPER_RELEASED, "HELPER_RELEASED"},
};

std::shared_ptr<IAVMetadataHelperService> AVMetadataHelperServer::Create()
{
    std::shared_ptr<AVMetadataHelperServer> server = std::make_shared<AVMetadataHelperServer>();
    CHECK_AND_RETURN_RET_LOG(server != nullptr, nullptr, "Failed to new AVMetadataHelperServer");
    return server;
}

AVMetadataHelperServer::AVMetadataHelperServer()
    : taskQue_("AVMetadata")
{
    appUid_ = IPCSkeleton::GetCallingUid();
    appPid_ = IPCSkeleton::GetCallingPid();
    appName_ = GetClientBundleName(appUid_);
    appTokenId_ = IPCSkeleton::GetCallingTokenID();
    MEDIA_LOGI("appUid: %{public}d, appPid: %{public}d, appName: %{public}s", appUid_, appPid_, appName_.c_str());
    (void)taskQue_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVMetadataHelperServer::~AVMetadataHelperServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<void>>([&, this] {
        avMetadataHelperEngine_ = nullptr;
        uriHelper_ = nullptr;
    });
    (void)taskQue_.EnqueueTask(task, true);
    (void)task->GetResult();
    taskQue_.Stop();
}

int32_t AVMetadataHelperServer::SetSource(const std::string &uri, int32_t usage)
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::SetSource_uri");
    MEDIA_LOGD("Current uri is : %{private}s %{public}u", uri.c_str(), usage);
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), MSERR_INVALID_VAL, "uri is empty");
    int32_t setSourceRes = MSERR_OK;
    std::atomic<bool> isInitEngineEnd = false;

    auto task = std::make_shared<TaskHandler<int32_t>>([this, usage, uri, &isInitEngineEnd, &setSourceRes] {
        MediaTrace trace("AVMetadataHelperServer::SetSource_uri_task");
        {
            std::unique_lock<std::mutex> lock(mutex_);
            uriHelper_ = std::make_unique<UriHelper>(uri);
            int32_t res = CheckSourceByUriHelper();
            isInitEngineEnd = true;
            if (res != MSERR_OK) {
                setSourceRes = res;
                ipcReturnCond_.notify_all();
                return res;
            }
            ipcReturnCond_.notify_all();
        }
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
            static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
            "Failed to create avmetadatahelper engine");
        int32_t ret = avMetadataHelperEngine_->SetSource(uriHelper_->FormattedUri(), usage);
        currState_ = ret == MSERR_OK ? HELPER_PREPARED : HELPER_STATE_ERROR;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "0x%{public}06" PRIXPTR " SetSource failed", FAKE_POINTER(this));
        return ret;
    });
    CHECK_AND_RETURN_RET_LOG(task != nullptr, MSERR_NO_MEMORY, "Failed to create task");
    taskQue_.EnqueueTask(task);
    ipcReturnCond_.wait(lock, [this, &isInitEngineEnd] {
        return isInitEngineEnd.load() || isInterrupted_.load();
    });
    CHECK_AND_RETURN_RET_LOG(isInterrupted_.load() == false, MSERR_INVALID_OPERATION, "SetSource interrupted");
    return setSourceRes;
}

int32_t AVMetadataHelperServer::SetAVMetadataCaller(AVMetadataCaller caller)
{
    MediaTrace trace("AVMetadataHelperServer::SetAVMetadataCaller");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, static_cast<int32_t>(MSERR_INVALID_OPERATION),
        "avMetadataHelperEngine_ is nullptr");
    return avMetadataHelperEngine_->SetAVMetadataCaller(caller);
}

int32_t AVMetadataHelperServer::SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header)
{
    MediaTrace trace("AVMetadataHelperServer::SetUrlSource");
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("Current uri is : %{private}s", uri.c_str());
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), MSERR_INVALID_VAL, "uri is empty");
    int32_t setSourceRes = MSERR_OK;
    std::atomic<bool> isInitEngineEnd = false;

    auto task = std::make_shared<TaskHandler<int32_t>>([this, header, uri, &isInitEngineEnd, &setSourceRes] {
        MediaTrace trace("AVMetadataHelperServer::SetUrlSource_task");
        {
            std::unique_lock<std::mutex> lock(mutex_);
            int32_t res = InitEngine(uri);
            isInitEngineEnd = true;
            if (res != MSERR_OK) {
                setSourceRes = res;
                ipcReturnCond_.notify_all();
                return res;
            }
            ipcReturnCond_.notify_all();
        }
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
            static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
            "Failed to create avmetadatahelper engine");
        int32_t ret = avMetadataHelperEngine_->SetUrlSource(uri, header);
        currState_ = ret == MSERR_OK ? HELPER_PREPARED : HELPER_STATE_ERROR;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "0x%{public}06" PRIXPTR " SetUrlSource failed",
            FAKE_POINTER(this));
        return ret;
    });
    CHECK_AND_RETURN_RET_LOG(task != nullptr, MSERR_NO_MEMORY, "Failed to create task");
    taskQue_.EnqueueTask(task);
    ipcReturnCond_.wait(lock, [this, &isInitEngineEnd] {
        return isInitEngineEnd.load() || isInterrupted_.load();
    });
    CHECK_AND_RETURN_RET_LOG(isInterrupted_.load() == false, MSERR_INVALID_OPERATION, "SetUrlSource interrupted");
    return setSourceRes;
}

int32_t AVMetadataHelperServer::CheckSourceByUriHelper()
{
    CHECK_AND_RETURN_RET_LOG(uriHelper_ != nullptr, MSERR_NO_MEMORY, "Failed to create UriHelper");
    CHECK_AND_RETURN_RET_LOG(!uriHelper_->FormattedUri().empty(),
                             MSERR_INVALID_VAL,
                             "Failed to construct formatted uri");
    CHECK_AND_RETURN_RET_LOG(uriHelper_->AccessCheck(UriHelper::URI_READ),
                             MSERR_INVALID_VAL,
                             "Failed to read the file");
    return InitEngine(uriHelper_->FormattedUri());
}

int32_t AVMetadataHelperServer::SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage)
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::SetSource_fd");
    MEDIA_LOGD("Current is fd source, offset: %{public}" PRIi64 ", size: %{public}" PRIi64 " usage: %{public}u",
               offset, size, usage);
    int32_t setSourceRes = MSERR_OK;
    std::atomic<bool> isInitEngineEnd = false;

    auto task = std::make_shared<TaskHandler<int32_t>>([this, fd, offset, size,
                                                        usage, &isInitEngineEnd, &setSourceRes] {
        MediaTrace trace("AVMetadataHelperServer::SetSource_fd_task");
        {
            std::unique_lock<std::mutex> lock(mutex_);
            uriHelper_ = std::make_unique<UriHelper>(fd, offset, size);
            int32_t res = CheckSourceByUriHelper();
            isInitEngineEnd = true;
            if (res != MSERR_OK) {
                setSourceRes = res;
                ipcReturnCond_.notify_all();
                return res;
            }
            ipcReturnCond_.notify_all();
        }
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
            static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
            "Failed to create avmetadatahelper engine");

        int32_t ret = avMetadataHelperEngine_->SetSource(uriHelper_->FormattedUri(), usage);
        currState_ = ret == MSERR_OK ? HELPER_PREPARED : HELPER_STATE_ERROR;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "0x%{public}06" PRIXPTR " SetSource failed", FAKE_POINTER(this));
        return ret;
    });
    CHECK_AND_RETURN_RET_LOG(task != nullptr, MSERR_NO_MEMORY, "Failed to create task");
    taskQue_.EnqueueTask(task);
    ipcReturnCond_.wait(lock, [this, &isInitEngineEnd] {
        return isInitEngineEnd.load() || isInterrupted_.load();
    });
    CHECK_AND_RETURN_RET_LOG(isInterrupted_.load() == false, MSERR_INVALID_OPERATION, "SetSource interrupted");
    return setSourceRes;
}

int32_t AVMetadataHelperServer::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::SetSource dataSrc");
    MEDIA_LOGD("AVMetadataHelperServer SetSource");
    CHECK_AND_RETURN_RET_LOG(dataSrc != nullptr, MSERR_INVALID_VAL, "data source is nullptr");
    dataSrc_ = dataSrc;
    int32_t setSourceRes = MSERR_OK;
    std::atomic<bool> isInitEngineEnd = false;
    
    auto task = std::make_shared<TaskHandler<int32_t>>([this, dataSrc, &isInitEngineEnd, &setSourceRes] {
        MediaTrace trace("AVMetadataHelperServer::SetSource dataSrc_task");
        {
            std::unique_lock<std::mutex> lock(mutex_);
            int32_t res = InitEngine("media data source");
            isInitEngineEnd = true;
            if (res != MSERR_OK) {
                setSourceRes = res;
                ipcReturnCond_.notify_all();
                return res;
            }
            ipcReturnCond_.notify_all();
        }
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
            static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
            "Failed to create avmetadatahelper engine");
        int32_t ret = avMetadataHelperEngine_->SetSource(dataSrc);
        currState_ = ret == MSERR_OK ? HELPER_PREPARED : HELPER_STATE_ERROR;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetSource failed!");

        int64_t size = 0;
        (void)dataSrc->GetSize(size);
        if (size == -1) {
            config_.looping = false;
            isLiveStream_ = true;
        }
        return ret;
    });
    CHECK_AND_RETURN_RET_LOG(task != nullptr, MSERR_NO_MEMORY, "Failed to create task");
    taskQue_.EnqueueTask(task);
    ipcReturnCond_.wait(lock, [this, &isInitEngineEnd] {
        return isInitEngineEnd.load() || isInterrupted_.load();
    });
    CHECK_AND_RETURN_RET_LOG(isInterrupted_.load() == false, MSERR_INVALID_OPERATION, "SetSource interrupted");
    return setSourceRes;
}

int32_t AVMetadataHelperServer::InitEngine(const std::string &uri)
{
    auto engineFactory = EngineFactoryRepo::Instance().GetEngineFactory(
        IEngineFactory::Scene::SCENE_AVMETADATA, appUid_, uri);
    CHECK_AND_RETURN_RET_LOG(engineFactory != nullptr,
        static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
        "Failed to get engine factory");
    avMetadataHelperEngine_ = engineFactory->CreateAVMetadataHelperEngine(appUid_, appPid_, appTokenId_, appName_);
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
        static_cast<int32_t>(MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED),
        "Failed to create avmetadatahelper engine");
    return MSERR_OK;
}

std::string AVMetadataHelperServer::ResolveMetadata(int32_t key)
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::ResolveMetadata_key");
    MEDIA_LOGD("Key is %{public}d", key);
    auto task = std::make_shared<TaskHandler<std::string>>([this, key] {
        MediaTrace trace("AVMetadataHelperServer::ResolveMetadata_key_task");
        std::string err = "";
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->ResolveMetadata(key);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, "", "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), "", "task has been cleared");
    ChangeState(HelperStates::HELPER_CALL_DONE);
    return result.Value();
}

std::unordered_map<int32_t, std::string> AVMetadataHelperServer::ResolveMetadata()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::ResolveMetadata");
    auto task = std::make_shared<TaskHandler<std::unordered_map<int32_t, std::string>>>([this] {
        MediaTrace trace("AVMetadataHelperServer::ResolveMetadata_task");
        std::unordered_map<int32_t, std::string> err;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->ResolveMetadata();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, {}, "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), {}, "task has been cleared");
    ChangeState(HelperStates::HELPER_CALL_DONE);
    return result.Value();
}

std::shared_ptr<Meta> AVMetadataHelperServer::GetAVMetadata()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::ResolveMetadata");
    auto task = std::make_shared<TaskHandler<std::shared_ptr<Meta>>>([this] {
        MediaTrace trace("AVMetadataHelperServer::ResolveMetadata_task");
        std::shared_ptr<Meta> err = nullptr;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->GetAVMetadata();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, {}, "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), {}, "task has been cleared");
    ChangeState(HelperStates::HELPER_CALL_DONE);
    return result.Value();
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperServer::FetchArtPicture()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::FetchArtPicture");
    auto task = std::make_shared<TaskHandler<std::shared_ptr<AVSharedMemory>>>([this] {
        MediaTrace trace("AVMetadataHelperServer::FetchArtPicture_task");
        std::shared_ptr<AVSharedMemory> err = nullptr;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->FetchArtPicture();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), nullptr, "task has been cleared");
    if (result.Value() == nullptr) {
        MEDIA_LOGE("FetchArtPicture result is nullptr.");
        NotifyErrorCallback(HelperErrorType::INVALID_RESULT, "FetchArtPicture result is nullptr.");
        return nullptr;
    }
    ChangeState(HelperStates::HELPER_CALL_DONE);
    return result.Value();
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperServer::FetchFrameAtTime(int64_t timeUs, int32_t option,
    const OutputConfiguration &param)
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("AVMetadataHelperServer::FetchFrameAtTime");
    auto task = std::make_shared<TaskHandler<std::shared_ptr<AVSharedMemory>>>([this, timeUs, option, param] {
        MediaTrace trace("AVMetadataHelperServer::FetchFrameAtTime_task");
        std::shared_ptr<AVSharedMemory> err = nullptr;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->FetchFrameAtTime(timeUs, option, param);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), nullptr, "task has been cleared");
    ChangeState(HelperStates::HELPER_CALL_DONE);
    return result.Value();
}

std::shared_ptr<AVBuffer> AVMetadataHelperServer::FetchFrameYuv(int64_t timeUs, int32_t option,
    const OutputConfiguration &param)
{
    MediaTrace trace("AVMetadataHelperServer::FetchFrameAtTime");
    std::unique_lock<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<std::shared_ptr<AVBuffer>>>([this, timeUs, option, param] {
        MediaTrace trace("AVMetadataHelperServer::FetchFrameAtTime_task");
        std::shared_ptr<AVBuffer> err = nullptr;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, err, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->FetchFrameYuv(timeUs, option, param);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "EnqueueTask failed");
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), nullptr, "task has been cleared");
    return result.Value();
}

int32_t AVMetadataHelperServer::CancelAllFetchFrames()
{
    MediaTrace trace("AVMetadataHelperServer::CancelAllFetchFrames");
    std::unique_lock<std::mutex> lock(mutex_);
    isCanceled_ = true;
    return MSERR_OK;
}

int32_t AVMetadataHelperServer::FetchFrameYuvs(const std::vector<int64_t>& timeUsVector, int32_t option,
    const PixelMapParams &param)
{
    MediaTrace trace("AVMetadataHelperServer::FetchFrameYuvs");
    std::unique_lock<std::mutex> lock(mutex_);
    std::shared_ptr<AVBuffer> result = nullptr;
    OutputConfiguration config = { .dstWidth = param.dstWidth,
                                   .dstHeight = param.dstHeight,
                                   .colorFormat = param.colorFormat };
    if (isCanceled_.load()) {isCanceled_ = false;}

    auto task = std::make_shared<TaskHandler<int32_t>>([this, timeUsVector, option, config, param] {
        MediaTrace trace("AVMetadataHelperServer::FetchFrameAtTime_task");
        std::shared_ptr<AVBuffer> err(AVBuffer::CreateAVBuffer());
        std::shared_ptr<AVBuffer> frameBuffer_ = nullptr;
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr,
            MSERR_EXT_API9_SERVICE_DIED, "avMetadataHelperEngine_ is nullptr");
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE,
            MSERR_EXT_API9_SERVICE_DIED);
        int64_t actualTimeUs = 0;
        for (const auto& timeUs : timeUsVector) {
            if (isCanceled_.load()) {
                FrameInfo frameinfo_ = {NO_ERR, timeUs, 0, FETCH_CANCELED};
                NotifyPixelCompleteCallback(HELPER_INFO_TYPE_PIXEL, err, frameinfo_, param);
                continue;
            }
            if (timeUs < 0) {
                FrameInfo frameinfo_ = {UNSUPPORTED_FORMAT, timeUs, 0, FETCH_FAILED};
                NotifyPixelCompleteCallback(HELPER_INFO_TYPE_PIXEL, err, frameinfo_, param);
                continue;
            }
            bool errCallback = false;
            frameBuffer_ = avMetadataHelperEngine_->FetchFrameYuvs(timeUs, option, config, errCallback);
            if (errCallback == true) {
                FrameInfo frameinfo_ = {FETCH_TIMEOUT, timeUs, 0, FETCH_FAILED};
                NotifyPixelCompleteCallback(HELPER_INFO_TYPE_PIXEL, err, frameinfo_, param);
                continue;
            } else if (frameBuffer_ == nullptr) {
                FrameInfo frameinfo_ = {OPERATION_NOT_ALLOWED, timeUs, 0, FETCH_FAILED};
                NotifyPixelCompleteCallback(HELPER_INFO_TYPE_PIXEL, err, frameinfo_, param);
                continue;
            } else {
                actualTimeUs = frameBuffer_->pts_;
                FrameInfo frameinfo_ = {NO_ERR, timeUs, actualTimeUs, FETCH_SUCCEEDED};
                NotifyPixelCompleteCallback(HELPER_INFO_TYPE_PIXEL, frameBuffer_, frameinfo_, param);
            }
        }
        return MSERR_EXT_API9_OK;
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    return ret == MSERR_OK? MSERR_OK : MSERR_EXT_API9_SERVICE_DIED;
}

void AVMetadataHelperServer::Release()
{
    MediaTrace trace("AVMetadataHelperServer::Release");
    {
        auto avMetadataHelperEngine = avMetadataHelperEngine_;
        CHECK_AND_RETURN_LOG(avMetadataHelperEngine != nullptr, "avMetadataHelperEngine_ is nullptr");
        avMetadataHelperEngine->SetInterruptState(true);
    }
    
    auto task = std::make_shared<TaskHandler<void>>([&, this] {
        avMetadataHelperEngine_ = nullptr;
        uriHelper_ = nullptr;
        ChangeState(HelperStates::HELPER_RELEASED);
        {
            std::lock_guard<std::mutex> lockCb(mutexCb_);
            helperCb_ = nullptr;
        }
    });
    (void)taskQue_.EnqueueTask(task, true);
    (void)task->GetResult();
    std::unique_lock<std::mutex> lock(mutex_);
    isInterrupted_ = true;
    ipcReturnCond_.notify_all();
}

int32_t AVMetadataHelperServer::SetHelperCallback(const std::shared_ptr<HelperCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "callback is nullptr");

    if (currState_ != HELPER_IDLE) {
        MEDIA_LOGE("Can not SetHelperCallback, currentState is %{public}s",
            GetStatusDescription(currState_).c_str());
        return MSERR_INVALID_OPERATION;
    }

    {
        std::lock_guard<std::mutex> lockCb(mutexCb_);
        helperCb_ = callback;
    }
    return MSERR_OK;
}

int32_t AVMetadataHelperServer::GetTimeByFrameIndex(uint32_t index, uint64_t &time)
{
    MediaTrace trace("AVMetadataHelperServer::GetTimeByFrameIndex");
    std::unique_lock<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, &timeUs = time, index] {
        MediaTrace trace("AVMetadataHelperServer::GetTimeByFrameIndex_task");
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, static_cast<int32_t>(MSERR_NO_MEMORY),
                                 "avMetadataHelperEngine_ is nullptr");
        int32_t err = static_cast<int32_t>(MSERR_INVALID_STATE);
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->GetTimeByFrameIndex(index, timeUs);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_NO_MEMORY, "EnqueueTask failed");
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_STATE, "task has been cleared");
    return result.Value();
}

int32_t AVMetadataHelperServer::GetFrameIndexByTime(uint64_t time, uint32_t &index)
{
    MediaTrace trace("AVMetadataHelperServer::GetFrameIndexByTime");
    std::unique_lock<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, &index = index, time] {
        MediaTrace trace("AVMetadataHelperServer::GetFrameIndexByTime_task");
        CHECK_AND_RETURN_RET_LOG(avMetadataHelperEngine_ != nullptr, static_cast<int32_t>(MSERR_NO_MEMORY),
                                 "avMetadataHelperEngine_ is nullptr");
        int32_t err = static_cast<int32_t>(MSERR_INVALID_STATE);
        CHECK_AND_RETURN_RET(currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE, err);
        return avMetadataHelperEngine_->GetFrameIndexByTime(time, index);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_STATE, "task has been cleared");
    return result.Value();
}

void AVMetadataHelperServer::ChangeState(const HelperStates state)
{
    switch (state) {
        case HELPER_PREPARED:
            if (currState_ == HELPER_IDLE) {
                currState_ = HELPER_PREPARED;
                NotifyInfoCallback(HELPER_INFO_TYPE_STATE_CHANGE, currState_);
            } else {
                NotifyErrorCallback(HelperErrorType::INVALID_OPERATION, "State error, current Operation is invalid.");
            }
            break;
        case HELPER_CALL_DONE:
            if (currState_ == HELPER_CALL_DONE || currState_ == HELPER_PREPARED) {
                currState_ = HELPER_CALL_DONE;
                NotifyInfoCallback(HELPER_INFO_TYPE_STATE_CHANGE, currState_);
            } else {
                NotifyErrorCallback(HelperErrorType::INVALID_OPERATION, "State error, current Operation is invalid.");
            }
            break;
        case HELPER_RELEASED:
            if (currState_ == HELPER_IDLE || currState_ == HELPER_PREPARED || currState_ == HELPER_CALL_DONE) {
                currState_ = HELPER_RELEASED;
                NotifyInfoCallback(HELPER_INFO_TYPE_STATE_CHANGE, currState_);
            } else {
                NotifyErrorCallback(HelperErrorType::INVALID_OPERATION, "State error, current Operation is invalid.");
            }
            break;
        case HELPER_STATE_ERROR:
            currState_ = HELPER_STATE_ERROR;
            NotifyInfoCallback(HELPER_INFO_TYPE_STATE_CHANGE, currState_);
            break;
        default:
            MEDIA_LOGI("Changed state is invalid.");
            break;
    }
}

void AVMetadataHelperServer::NotifyErrorCallback(int32_t code, const std::string msg)
{
    std::lock_guard<std::mutex> lockCb(mutexCb_);
    MEDIA_LOGD("NotifyErrorCallback error code: %{public}d", code);
    if (helperCb_ != nullptr) {
        helperCb_->OnError(code, msg);
    }
}

void AVMetadataHelperServer::NotifyInfoCallback(HelperOnInfoType type, int32_t extra)
{
    std::lock_guard<std::mutex> lockCb(mutexCb_);
    MEDIA_LOGD("NotifyInfoCallback, extra: %{public}d", extra);
    if (helperCb_ != nullptr) {
        helperCb_->OnInfo(type, extra);
    }
}

void AVMetadataHelperServer::NotifyPixelCompleteCallback(HelperOnInfoType type,
                                                         const std::shared_ptr<AVBuffer> &reAvbuffer_,
                                                         const FrameInfo &info,
                                                         const PixelMapParams &param)
{
    std::lock_guard<std::mutex> lockCb(mutexCb_);
    CHECK_AND_RETURN_LOG(helperCb_ != nullptr, "AVMetadataHelperServer CallBack Is Null");
    helperCb_->OnPixelComplete(type, reAvbuffer_, info, param);
}

const std::string &AVMetadataHelperServer::GetStatusDescription(int32_t status)
{
    static const std::string ILLEGAL_STATE = "PLAYER_STATUS_ILLEGAL";
    if (status < HELPER_STATE_ERROR || status > HELPER_RELEASED) {
        return ILLEGAL_STATE;
    }

    return STATUS_TO_STATUS_DESCRIPTION_TABLE.find(status)->second;
}
} // namespace Media
} // namespace OHOS
