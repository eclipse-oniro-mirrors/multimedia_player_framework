/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "avdownloader_manager_napi.h"
#include "media_log.h"
#include "media_errors.h"
#include "common_napi.h"
#include "media_source_napi.h"
#include "scope_guard.h"
#include <cstdint>
#include <chrono>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVDownloaderManager"};
constexpr int32_t ERR_AVD_PARAM_OUT_OF_RANGE = 5400108;
constexpr int32_t ERR_AVD_OPERATION_NOT_PERMIT = 5400102;
}

namespace OHOS {
namespace Media {
namespace {
std::string StateToString(AVDownloadTaskState state)
{
    switch (state) {
        case AVDownloadTaskState::INIT:      return "init";
        case AVDownloadTaskState::QUEUED:    return "queued";
        case AVDownloadTaskState::RUNNING:   return "running";
        case AVDownloadTaskState::COMPLETED: return "completed";
        case AVDownloadTaskState::PAUSED:    return "paused";
        case AVDownloadTaskState::REMOVING:  return "removing";
        case AVDownloadTaskState::ERROR:     return "error";
        default:                              return "init";
    }
}

napi_value FailInit(napi_env env, napi_ref &ref, const char *msg)
{
    MEDIA_LOGE("%{public}s", msg);
    if (ref != nullptr) {
        napi_delete_reference(env, ref);
        ref = nullptr;
    }
    return nullptr;
}
}

thread_local napi_ref AVDownloaderManagerNapi::constructor_ = nullptr;

AVDownloaderManagerNapi::AVDownloaderManagerNapi()
    : downloaderManager_(AVDownloaderManagerFactory::Create())
{
    MEDIA_LOGD("AVDownloaderManagerNapi Instances create");
    auto deleter = [](AVDownloaderManagerNapi*) { /* napi管理，不删除 */ };
    selfRef_ = std::shared_ptr<AVDownloaderManagerNapi>(this, deleter);
    if (downloaderManager_) {
        downloaderManager_->SetManagerCallback(selfRef_);
    }
}

AVDownloaderManagerNapi::~AVDownloaderManagerNapi()
{
    MEDIA_LOGD("AVDownloaderManagerNapi Instances destroy");
    statusChangeCallback_.reset();
    progressChangeCallback_.reset();
    if (downloaderManager_) {
        downloaderManager_->Release();
        downloaderManager_.reset();
    }
}

std::string AVDownloaderManagerNapi::GenerateTaskId()
{
    return std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
}

std::string AVDownloaderManagerNapi::GetTaskCacheDir(const std::string &taskId)
{
    if (downloaderManager_) {
        return downloaderManager_->GetTaskCacheDirectory(taskId);
    }
    auto it = taskIdToCacheDir_.find(taskId);
    if (it != taskIdToCacheDir_.end()) {
        return it->second;
    }
    return "";
}

void AVDownloaderManagerNapi::ThrowError(napi_env env, int32_t code, const std::string &errMessage)
{
    napi_throw_error(env, std::to_string(code).c_str(), errMessage.c_str());
}

void AVDownloaderManagerNapi::OnStatusChange(const std::string &taskId, AVDownloadTaskState state)
{
    MEDIA_LOGI("AVDownloaderManagerNapi::OnStatusChange taskId: %{public}s, state: %{public}d", taskId.c_str(), state);
    TriggerStatusCallback(taskId, state);
}

void AVDownloaderManagerNapi::OnProgressChange(const std::string &taskId, double progress)
{
    MEDIA_LOGI("AVDownloaderManagerNapi::OnProgressChange taskId: %{public}s, progress: %{public}f",
        taskId.c_str(), progress);
    TriggerProgressCallback(taskId, progress);
}

void AVDownloaderManagerNapi::TriggerStatusCallback(const std::string &taskId, AVDownloadTaskState state)
{
    std::shared_ptr<AutoRef> cbHolder;
    {
        std::lock_guard<std::mutex> lock(cbMutex_);
        if (statusChangeCallback_ == nullptr) {
            return;
        }
        cbHolder = statusChangeCallback_;
    }

    napi_env env = cbHolder->env_;
    auto task = [cbHolder, taskId, state]() {
        std::string request = "TriggerStatusCallback";
        MEDIA_LOGI("JsCallBack %{public}s, start", request.c_str());

        do {
            CHECK_AND_BREAK_LOG(cbHolder != nullptr && cbHolder->cb_ != nullptr, "callback ref is nullptr");

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(cbHolder->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "scope is nullptr");
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(cbHolder->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(cbHolder->env_, cbHolder->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "get reference value fail");

            napi_value args[2] = { nullptr };
            napi_create_string_utf8(cbHolder->env_, taskId.c_str(), NAPI_AUTO_LENGTH, &args[0]);
            std::string stateStr = StateToString(state);
            napi_create_string_utf8(cbHolder->env_, stateStr.c_str(), NAPI_AUTO_LENGTH, &args[1]);

            napi_value result = nullptr;
            nstatus = napi_call_function(cbHolder->env_, nullptr, jsCallback, 2, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "fail to napi call function");
        } while (0);
    };

    auto ret = napi_send_event(env, task, napi_eprio_high, "AVDownloaderManagerNapi::TriggerStatusCallback");
    if (ret != napi_ok) {
        MEDIA_LOGE("Failed to SendEvent, ret = %{public}d", ret);
    }
}

void AVDownloaderManagerNapi::TriggerProgressCallback(const std::string &taskId, double progress)
{
    std::shared_ptr<AutoRef> cbHolder;
    {
        std::lock_guard<std::mutex> lock(cbMutex_);
        if (progressChangeCallback_ == nullptr) {
            return;
        }
        cbHolder = progressChangeCallback_;
    }

    napi_env env = cbHolder->env_;
    auto task = [cbHolder, taskId, progress]() {
        std::string request = "TriggerProgressCallback";
        MEDIA_LOGI("JsCallBack %{public}s, start", request.c_str());

        do {
            CHECK_AND_BREAK_LOG(cbHolder != nullptr && cbHolder->cb_ != nullptr, "callback ref is nullptr");

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(cbHolder->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "scope is nullptr");
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(cbHolder->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(cbHolder->env_, cbHolder->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "get reference value fail");

            napi_value args[2] = { nullptr };
            napi_create_string_utf8(cbHolder->env_, taskId.c_str(), NAPI_AUTO_LENGTH, &args[0]);
            napi_create_double(cbHolder->env_, progress, &args[1]);

            napi_value result = nullptr;
            nstatus = napi_call_function(cbHolder->env_, nullptr, jsCallback, 2, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "fail to napi call function");
        } while (0);
    };

    auto ret = napi_send_event(env, task, napi_eprio_high, "AVDownloaderManagerNapi::TriggerProgressCallback");
    if (ret != napi_ok) {
        MEDIA_LOGE("Failed to SendEvent, ret = %{public}d", ret);
    }
}

napi_value AVDownloaderManagerNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        {"createAVDownloaderManager", nullptr, CreateAVDownloaderManager,
            nullptr, nullptr, nullptr, napi_writable, nullptr},
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("allowsCellularAccess", AllowsCellularAccess),
        DECLARE_NAPI_FUNCTION("setRequestTimeout", SetRequestTimeout),
        DECLARE_NAPI_FUNCTION("addAVDownloadTask", AddAVDownloadTask),
        DECLARE_NAPI_FUNCTION("removeDownloadTask", RemoveDownloadTask),
        DECLARE_NAPI_FUNCTION("pauseDownloadTask", PauseDownloadTask),
        DECLARE_NAPI_FUNCTION("resumeDownloadTask", ResumeDownloadTask),
        DECLARE_NAPI_FUNCTION("getDownloadTasks", GetDownloadTasks),
        DECLARE_NAPI_FUNCTION("getTaskCacheDirectory", GetTaskCacheDirectory),
        DECLARE_NAPI_FUNCTION("getTaskStatus", GetTaskStatus),
        DECLARE_NAPI_FUNCTION("getTaskProgress", GetTaskProgress),
        DECLARE_NAPI_FUNCTION("onStatusChange", OnStatusChange),
        DECLARE_NAPI_FUNCTION("onProgressChange", OnProgressChange),
        DECLARE_NAPI_FUNCTION("offStatusChange", OffStatusChange),
        DECLARE_NAPI_FUNCTION("offProgressChange", OffProgressChange),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, "AVDownloaderManager", NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        return FailInit(env, constructor_, "failed to define class");
    }

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    if (status != napi_ok) {
        return FailInit(env, constructor_, "failed to define static properties");
    }

    status = napi_set_named_property(env, exports, "AVDownloaderManager", constructor);
    if (status != napi_ok) {
        return FailInit(env, constructor_, "failed to set named property");
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to create reference");

    return exports;
}

napi_value AVDownloaderManagerNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = new (std::nothrow) AVDownloaderManagerNapi();
    CHECK_AND_RETURN_RET_LOG(manager != nullptr, nullptr, "failed to new object");

    status = napi_wrap(env, thisArg, manager, Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        MEDIA_LOGE("failed to wrap");
        delete manager;
        return nullptr;
    }

    return thisArg;
}

void AVDownloaderManagerNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    AVDownloaderManagerNapi *manager = static_cast<AVDownloaderManagerNapi *>(nativeObject);
    manager->selfRef_.reset();
    delete manager;
}

napi_value AVDownloaderManagerNapi::CreateAVDownloaderManager(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("CreateAVDownloaderManager In");

    napi_value constructor = nullptr;
    napi_status ret = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_AND_RETURN_RET_LOG(ret == napi_ok && constructor != nullptr, nullptr, "failed to get constructor");

    napi_value instance = nullptr;
    ret = napi_new_instance(env, constructor, 0, nullptr, &instance);
    CHECK_AND_RETURN_RET_LOG(ret == napi_ok && instance != nullptr, nullptr, "failed to new instance");

    return instance;
}

napi_value AVDownloaderManagerNapi::AllowsCellularAccess(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("AllowsCellularAccess In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argCount >= 1, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_boolean) {
        return nullptr;
    }

    bool allow = false;
    napi_get_value_bool(env, args[0], &allow);
    MEDIA_LOGI("get allow: %{public}d", allow);
    manager->allowCellularAccess_ = allow;
    if (manager->downloaderManager_) {
        manager->downloaderManager_->SetAllowCellularAccess(allow);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::SetRequestTimeout(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("SetRequestTimeout In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argCount >= 1, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        return nullptr;
    }

    int32_t timeout = 0;
    napi_get_value_int32(env, args[0], &timeout);
    manager->requestTimeoutMs_ = timeout;
    if (manager->downloaderManager_) {
        manager->downloaderManager_->SetRequestTimeout(timeout);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::AddAVDownloadTask(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("AddAVDownloadTask In");

    size_t argCount = 2;
    napi_value args[2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < 1) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    std::shared_ptr<AVMediaSourceTmp> srcTmp = nullptr;
    if (argCount >= 1) {
        MEDIA_LOGI("check args: argCount >= 1");
        srcTmp = MediaSourceNapi::GetMediaSource(env, args[0]);
        if (srcTmp == nullptr) {
            ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Invalid parameter: media source is null");
            return nullptr;
        }
    }

    std::string taskId;
    MEDIA_LOGI("check args: downloaderManager_: %{public}d", manager->downloaderManager_ == nullptr);
    if (!manager->downloaderManager_) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return nullptr;
    }
    if (srcTmp) {
        MEDIA_LOGI("AddDownloadTask In");
        auto pluginSource = std::make_shared<Plugins::MediaSource>(srcTmp->url, srcTmp->header);
        taskId = manager->downloaderManager_->AddDownloadTask(pluginSource);
        if (taskId.empty()) {
            ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed: failed to add download task");
            return nullptr;
        }
        manager->taskIdToUrl_[taskId] = srcTmp->url;
    }

    napi_value result = nullptr;
    napi_create_string_utf8(env, taskId.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::RemoveDownloadTask(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("RemoveDownloadTask In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_string) {
            char taskId[256] = {0};
            size_t length = 0;
            napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
            if (nstatus != napi_ok || length == 0) {
                ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
                return nullptr;
            }
            if (manager->taskIdToUrl_.find(taskId) == manager->taskIdToUrl_.end()) {
                ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
                return nullptr;
            }
            if (manager->downloaderManager_) {
                int32_t errCode = manager->downloaderManager_->RemoveDownloadTask(taskId);
                if (errCode != MSERR_OK) {
                    ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed");
                    return nullptr;
                }
            }
            manager->taskIdToUrl_.erase(taskId);
            manager->taskIdToCacheDir_.erase(taskId);
        }
    } else {
        if (manager->downloaderManager_) {
            auto tasks = manager->downloaderManager_->GetDownloadTasks();
            for (const auto &tid : tasks) {
                int32_t errCode = manager->downloaderManager_->RemoveDownloadTask(tid);
                if (errCode != MSERR_OK) {
                    ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed");
                    return nullptr;
                }
            }
        }
        manager->taskIdToUrl_.clear();
        manager->taskIdToCacheDir_.clear();
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::PauseDownloadTask(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("PauseDownloadTask In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_string) {
            char taskId[256] = {0};
            size_t length = 0;
            napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
            if (nstatus != napi_ok || length == 0) {
                ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
                return nullptr;
            }
            if (manager->taskIdToUrl_.find(taskId) == manager->taskIdToUrl_.end()) {
                ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
                return nullptr;
            }
            if (manager->downloaderManager_) {
                int32_t errCode = manager->downloaderManager_->PauseDownloadTask(taskId);
                if (errCode != MSERR_OK) {
                    ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed");
                    return nullptr;
                }
            }
        }
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::ResumeDownloadTask(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("ResumeDownloadTask In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_string) {
            char taskId[256] = {0};
            size_t length = 0;
            napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
            if (nstatus != napi_ok || length == 0) {
                ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
                return nullptr;
            }
            if (manager->taskIdToUrl_.find(taskId) == manager->taskIdToUrl_.end()) {
                ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
                return nullptr;
            }
            if (manager->downloaderManager_) {
                int32_t errCode = manager->downloaderManager_->ResumeDownloadTask(taskId);
                if (errCode != MSERR_OK) {
                    ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Operation not allowed");
                    return nullptr;
                }
            }
        }
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::GetDownloadTasks(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("GetDownloadTasks In");

    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    napi_value result = nullptr;
    napi_create_array(env, &result);

    std::vector<std::string> taskIds;
    if (manager->downloaderManager_) {
        taskIds = manager->downloaderManager_->GetDownloadTasks();
    }

    uint32_t index = 0;
    for (const auto &taskId : taskIds) {
        napi_value taskIdVal = nullptr;
        napi_create_string_utf8(env, taskId.c_str(), NAPI_AUTO_LENGTH, &taskIdVal);
        napi_set_element(env, result, index++, taskIdVal);
    }

    return result;
}

napi_value AVDownloaderManagerNapi::GetTaskCacheDirectory(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("GetTaskCacheDirectory In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < 1) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "Invalid parameter: taskId must be string");
        return nullptr;
    }

    char taskId[256] = {0};
    size_t length = 0;
    napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
    if (nstatus != napi_ok || length == 0) {
        ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
        return nullptr;
    }

    if (manager->taskIdToUrl_.find(taskId) == manager->taskIdToUrl_.end()) {
        ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
        return nullptr;
    }

    std::string cacheDir = manager->GetTaskCacheDir(taskId);

    napi_value result = nullptr;
    napi_create_string_utf8(env, cacheDir.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::GetTaskStatus(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("GetTaskStatus In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < 1) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    std::string stateStr = "init";
    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_string) {
            char taskId[256] = {0};
            size_t length = 0;
            napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
            if (nstatus != napi_ok || length == 0) {
                ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
                return nullptr;
            }

            AVDownloadTaskState state = AVDownloadTaskState::INIT;
            if (manager->downloaderManager_) {
                state = manager->downloaderManager_->GetTaskStatus(taskId);
                if (state == AVDownloadTaskState::ERROR) {
                    ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
                    return nullptr;
                }
            }
            stateStr = StateToString(state);
        }
    }

    napi_value result = nullptr;
    napi_create_string_utf8(env, stateStr.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::GetTaskProgress(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("GetTaskProgress In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < 1) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to get cb info");
        return nullptr;
    }

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    if (status != napi_ok || manager == nullptr) {
        ThrowError(env, ERR_OPERATION_NOT_PERMIT, "failed to unwrap");
        return nullptr;
    }

    double progress = 0.0;
    if (argCount >= 1 && manager->downloaderManager_) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_string) {
            char taskId[256] = {0};
            size_t length = 0;
            napi_status nstatus = napi_get_value_string_utf8(env, args[0], taskId, sizeof(taskId), &length);
            if (nstatus != napi_ok || length == 0) {
                ThrowError(env, ERR_AVD_PARAM_OUT_OF_RANGE, "Invalid taskId");
                return nullptr;
            }
            if (manager->taskIdToUrl_.find(taskId) == manager->taskIdToUrl_.end()) {
                ThrowError(env, ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
                return nullptr;
            }
            progress = manager->downloaderManager_->GetTaskProgress(taskId);
        }
    }

    napi_value result = nullptr;
    napi_create_double(env, progress, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::OnStatusChange(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("OnStatusChange In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argCount >= 1, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_function) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(manager->cbMutex_);
        napi_ref ref = nullptr;
        if (napi_create_reference(env, args[0], 1, &ref) == napi_ok && ref != nullptr) {
            manager->statusChangeCallback_ = std::make_shared<AutoRef>(env, ref, true);
        } else {
            manager->statusChangeCallback_.reset();
        }
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::OnProgressChange(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("OnProgressChange In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argCount >= 1, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_function) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(manager->cbMutex_);
        napi_ref ref = nullptr;
        if (napi_create_reference(env, args[0], 1, &ref) == napi_ok && ref != nullptr) {
            manager->progressChangeCallback_ = std::make_shared<AutoRef>(env, ref, true);
        } else {
            manager->progressChangeCallback_.reset();
        }
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::OffStatusChange(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("OffStatusChange In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_function) {
            std::lock_guard<std::mutex> lock(manager->cbMutex_);
            manager->statusChangeCallback_.reset();
        }
    } else {
        std::lock_guard<std::mutex> lock(manager->cbMutex_);
        manager->statusChangeCallback_.reset();
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::OffProgressChange(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("OffProgressChange In");

    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    if (argCount >= 1) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) == napi_ok && valueType == napi_function) {
            std::lock_guard<std::mutex> lock(manager->cbMutex_);
            manager->progressChangeCallback_.reset();
        }
    } else {
        std::lock_guard<std::mutex> lock(manager->cbMutex_);
        manager->progressChangeCallback_.reset();
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value AVDownloaderManagerNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("Release In");

    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to get cb info");

    AVDownloaderManagerNapi *manager = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&manager));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && manager != nullptr, nullptr, "failed to unwrap");

    {
        std::lock_guard<std::mutex> lock(manager->cbMutex_);
        manager->statusChangeCallback_.reset();
        manager->progressChangeCallback_.reset();
    }
    if (manager->downloaderManager_) {
        manager->downloaderManager_->Release();
    }
    manager->taskIdToUrl_.clear();
    manager->taskIdToCacheDir_.clear();

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

} // namespace Media
} // namespace OHOS