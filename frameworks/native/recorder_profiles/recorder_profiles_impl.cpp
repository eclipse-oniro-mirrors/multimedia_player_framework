/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "recorder_profiles_impl.h"
#include "media_log.h"
#include "media_errors.h"
#include "i_media_service.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderProfilesImpl"};
}

namespace OHOS {
namespace Media {
RecorderProfiles& RecorderProfilesFactory::CreateRecorderProfiles()
{
    return RecorderProfilesImpl::GetInstance();
}

RecorderProfiles& RecorderProfilesImpl::GetInstance()
{
    static RecorderProfilesImpl instance;
    instance.Init();
    return instance;
}

int32_t RecorderProfilesImpl::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (recorderProfilesService_ == nullptr) {
        recorderProfilesService_ = MediaServiceFactory::GetInstance().CreateRecorderProfilesService();
    }

    CHECK_AND_RETURN_RET_LOG(recorderProfilesService_ != nullptr,
        MSERR_NO_MEMORY, "failed to create RecorderProfiles service");
    return MSERR_OK;
}

std::shared_ptr<IRecorderProfilesService> RecorderProfilesImpl::GetRecorderProfilesService()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return recorderProfilesService_;
}

RecorderProfilesImpl::RecorderProfilesImpl()
{
    MEDIA_LOGD("RecorderProfilesImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderProfilesImpl::~RecorderProfilesImpl()
{
    std::shared_ptr<IRecorderProfilesService> service = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        service = recorderProfilesService_;
        recorderProfilesService_ = nullptr;
    }
    if (service != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyMediaProfileService(service);
    }
    MEDIA_LOGD("RecorderProfilesImpl:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool RecorderProfilesImpl::IsAudioRecorderConfigSupported(const AudioRecorderProfile &profile)
{
    std::shared_ptr<IRecorderProfilesService> service = GetRecorderProfilesService();
    CHECK_AND_RETURN_RET_LOG(service != nullptr, false, "RecorderProfiles service does not exist.");
    RecorderProfilesData profileData;
    profileData.recorderProfile.containerFormatType = profile.containerFormatType;
    profileData.recorderProfile.audioCodec = profile.audioCodec;
    profileData.recorderProfile.audioBitrate = profile.audioBitrate;
    profileData.recorderProfile.audioSampleRate = profile.audioSampleRate;
    profileData.recorderProfile.audioChannels = profile.audioChannels;
    return service->IsAudioRecorderConfigSupported(profileData);
}

bool RecorderProfilesImpl::HasVideoRecorderProfile(int32_t sourceId, int32_t qualityLevel)
{
    std::shared_ptr<IRecorderProfilesService> service = GetRecorderProfilesService();
    CHECK_AND_RETURN_RET_LOG(service != nullptr, false, "RecorderProfiles service does not exist.");
    return service->HasVideoRecorderProfile(sourceId, qualityLevel);
}

std::vector<std::shared_ptr<AudioRecorderCaps>> RecorderProfilesImpl::GetAudioRecorderCaps()
{
    std::shared_ptr<IRecorderProfilesService> service = GetRecorderProfilesService();
    CHECK_AND_RETURN_RET_LOG(service != nullptr,
        std::vector<std::shared_ptr<AudioRecorderCaps>>(), "RecorderProfiles service does not exist.");
    std::vector<RecorderProfilesData> capabilityArray = service->GetAudioRecorderCapsInfo();
    std::vector<std::shared_ptr<AudioRecorderCaps>> audioRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<AudioRecorderCaps> audioRecorderCaps = std::make_shared<AudioRecorderCaps>((*iter).audioCaps);
        CHECK_AND_RETURN_RET_LOG(audioRecorderCaps != nullptr, audioRecorderCapsArray, "Is null mem");
        audioRecorderCapsArray.push_back(audioRecorderCaps);
    }
    return audioRecorderCapsArray;
}

std::vector<std::shared_ptr<VideoRecorderCaps>> RecorderProfilesImpl::GetVideoRecorderCaps()
{
    std::shared_ptr<IRecorderProfilesService> service = GetRecorderProfilesService();
    CHECK_AND_RETURN_RET_LOG(service != nullptr,
        std::vector<std::shared_ptr<VideoRecorderCaps>>(), "RecorderProfiles service does not exist.");
    std::vector<RecorderProfilesData> capabilityArray = service->GetVideoRecorderCapsInfo();
    std::vector<std::shared_ptr<VideoRecorderCaps>> videoRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<VideoRecorderCaps> videoRecorderCaps = std::make_shared<VideoRecorderCaps>((*iter).videoCaps);
        CHECK_AND_RETURN_RET_LOG(videoRecorderCaps != nullptr, videoRecorderCapsArray, "Is null mem");
        videoRecorderCapsArray.push_back(videoRecorderCaps);
    }
    return videoRecorderCapsArray;
}

std::shared_ptr<VideoRecorderProfile> RecorderProfilesImpl::GetVideoRecorderProfile(int32_t sourceId,
    int32_t qualityLevel)
{
    std::shared_ptr<IRecorderProfilesService> service = GetRecorderProfilesService();
    CHECK_AND_RETURN_RET_LOG(service != nullptr,
        nullptr, "RecorderProfiles service does not exist.");
    RecorderProfilesData capability = service->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    CHECK_AND_RETURN_RET_LOG(videoRecorderProfile != nullptr, videoRecorderProfile, "Is null mem");
    return videoRecorderProfile;
}
}  // namespace Media
}  // namespace OHOS
