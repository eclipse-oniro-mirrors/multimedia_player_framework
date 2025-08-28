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

#ifndef MEDIA_LOCAL_H
#define MEDIA_LOCAL_H

#include "i_media_service.h"
#include "nocopyable.h"

class IAVCodecService;
class IAVCodecListService;
class IAVCodecService;
class IAVCodecListService;

namespace OHOS {
namespace Media {
class MediaLocal : public IMediaService, public NoCopyable {
public:
    MediaLocal() = default;
    ~MediaLocal() override = default;

    std::shared_ptr<IStandardMonitorService> GetMonitorProxy() override { return nullptr; };
    std::shared_ptr<IRecorderService> CreateRecorderService() override { return nullptr; };
    std::shared_ptr<ITransCoderService> CreateTransCoderService() override { return nullptr; };
    std::shared_ptr<IPlayerService> CreatePlayerService() override { return nullptr; };
    std::shared_ptr<IAVMetadataHelperService> CreateAVMetadataHelperService() override { return nullptr; };
    std::shared_ptr<IRecorderProfilesService> CreateRecorderProfilesService() override {return nullptr; };
    std::shared_ptr<IScreenCaptureService> CreateScreenCaptureService() override {return nullptr; };
    int32_t DestroyRecorderService(std::shared_ptr<IRecorderService> recorder) override { return 0; };
    int32_t DestroyTransCoderService(std::shared_ptr<ITransCoderService> transCoder) override { return 0; };
    int32_t DestroyPlayerService(std::shared_ptr<IPlayerService> player) override { return 0; };
    int32_t DestroyAVMetadataHelperService(std::shared_ptr<IAVMetadataHelperService> avMetadataHelper) override
    { return 0; };
    int32_t DestroyMediaProfileService(std::shared_ptr<IRecorderProfilesService> recorderProfiles) override
    { return 0; };
    int32_t DestroyScreenCaptureService(std::shared_ptr<IScreenCaptureService> screenCapture) override { return 0; };

    std::shared_ptr<IScreenCaptureMonitorService> CreateScreenCaptureMonitorService() override { return nullptr; }
    int32_t DestroyScreenCaptureMonitorService(std::shared_ptr<IScreenCaptureMonitorService>) override { return 0; }
    std::shared_ptr<IScreenCaptureController> CreateScreenCaptureControllerClient() override { return nullptr; }
    int32_t DestroyScreenCaptureControllerClient(std::shared_ptr<IScreenCaptureController>) override { return 0; }
    bool ReleaseClientListener() override { return true; }
    bool CanKillMediaService() override { return false; }
    std::vector<pid_t> GetPlayerPids() override { return {}; }
    int32_t ProxyForFreeze(const std::set<int32_t>&, bool) override { return 0; }
    int32_t ResetAllProxy() override { return 0; }
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_LOCAL_H
