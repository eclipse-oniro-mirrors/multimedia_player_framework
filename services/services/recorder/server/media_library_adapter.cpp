/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <iomanip>
#include <ctime>
#include "media_library_adapter.h"
#include "media_library_camera_manager.h"
#include "media_log.h"
#include "ipc_skeleton.h"
#include "media_dfx.h"
#include "hitrace/tracechain.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderServer"};
}

namespace OHOS {
namespace Media {
namespace MeidaLibraryAdapter {
constexpr std::string_view prefix = "VID_";
constexpr std::string_view connector = "_";
constexpr int32_t VIDEO_COUNT = 1;
class RecorderPhotoProxy : public PhotoProxy {
public:
    RecorderPhotoProxy() { }

    std::string GetDisplayName()
    {
        return GetTitle() + '.' + GetExtension();
    }

    void SetDisplayName(const std::string &displayName)
    {
        displayName_ = displayName;
    }

    std::string GetExtension() override
    {
        return "mp4";
    }

    std::string GetPhotoId() override
    {
        return "";
    }

    DeferredProcType GetDeferredProcType() override
    {
        return DeferredProcType::BACKGROUND;
    }

    int32_t GetWidth() override
    {
        return 0;
    }

    int32_t GetHeight() override
    {
        return 0;
    }

    void* GetFileDataAddr() override
    {
        return fileDataAddr_;
    }

    size_t GetFileSize() override
    {
        return 0;
    }

    void Release() override
    {
    }

    PhotoFormat GetFormat() override
    {
        return photoFormat_;
    }

    void SetFormat(PhotoFormat format)
    {
        photoFormat_ = format;
    }

    PhotoQuality GetPhotoQuality() override
    {
        return PhotoQuality::HIGH;
    }

    double GetLatitude() override
    {
        return 0.0;
    }

    double GetLongitude() override
    {
        return 0.0;
    }
    std::string GetTitle() override
    {
        return displayName_;
    }

    int32_t GetShootingMode() override
    {
        return 0;
    }

    std::string GetBurstKey() override
    {
        return "";
    }

    bool IsCoverPhoto() override
    {
        return false;
    }

    uint32_t GetCloudImageEnhanceFlag() override
    {
        return 0;
    };
private:
    void *fileDataAddr_ = nullptr;
    std::string displayName_;
    PhotoFormat photoFormat_ = PhotoFormat::RGBA;
};

struct tm *GetLocaltime(const time_t* clock, struct tm *result)
{
    struct tm *ptr = localtime(clock);
    if (!ptr) {
        return nullptr;
    }
    *result = *ptr;
    return result;
}

std::string CreateDisplayName()
{
    struct tm currentTime;
    std::string formattedTime = "";

    auto clock =  std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm* timeResult = GetLocaltime(&clock, &currentTime);
    int32_t yearWidth = 4;
    int32_t otherWidth = 2;
    int32_t startYear = 1900;
    char placeholder = '0';
    if (timeResult != nullptr) {
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1)
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_mday
           << connector << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_hour
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_min
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_LOGE("Failed to get current time.");
    }
    return formattedTime;
}

bool CreateMediaLibrary(int32_t &fd, std::string &uri)
{
    MediaTrace trace("RecorderServer::CreateMediaLibrary");
    MEDIA_LOGI("RecorderServer::CreateMediaLibrary");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, false, "Failed to get System ability manager");
    auto object = samgr->GetSystemAbility(PLAYER_DISTRIBUTED_SERVICE_ID);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, false, "object is null");
    auto mediaLibraryCameraManager = Media::MediaLibraryCameraManager::GetMediaLibraryCameraManager();
    CHECK_AND_RETURN_RET_LOG(mediaLibraryCameraManager != nullptr, false,
        "Error to init mediaLibraryCameraManager");
    mediaLibraryCameraManager->InitMediaLibraryCameraManager(object);
    const static int32_t INVALID_UID = -1;
    const static int32_t BASE_USER_RANGE = 200000;
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid <= INVALID_UID) {
        MEDIA_LOGD("Get INVALID_UID UID %{public}d", uid);
    }
    int32_t userId = uid / BASE_USER_RANGE;
    MEDIA_LOGD("get uid:%{public}d, userId:%{public}d, tokenId:%{public}d", uid, userId,
        IPCSkeleton::GetCallingTokenID());

    PhotoAssetProxyCallerInfo callerInfo {
        .callingUid = uid,
        .userId = userId,
        .callingTokenId = IPCSkeleton::GetCallingTokenID()
    };
    auto photoAssetProxy =
        mediaLibraryCameraManager->CreatePhotoAssetProxy(callerInfo, CameraShotType::VIDEO, VIDEO_COUNT);
    sptr<RecorderPhotoProxy> recorderPhotoProxy = new(std::nothrow) RecorderPhotoProxy();
    CHECK_AND_RETURN_RET_LOG(recorderPhotoProxy != nullptr, false,
        "Error to create recorderPhotoProxy");
    recorderPhotoProxy->SetDisplayName(CreateDisplayName());
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)recorderPhotoProxy);
    uri = photoAssetProxy->GetPhotoAssetUri();
    MEDIA_LOGD("video uri:%{public}s", uri.c_str());
    fd = mediaLibraryCameraManager->OpenAsset(uri, "rw");
    return true;
}
} // namespace MeidaLibraryAdapter
} // namespace Media
} // namespace OHOS