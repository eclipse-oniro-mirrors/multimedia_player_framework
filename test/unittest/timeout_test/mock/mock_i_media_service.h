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

#ifndef I_MEDIA_SERVICE_MOCK_H
#define I_MEDIA_SERVICE_MOCK_H

#include "gmock/gmock.h"
#include "i_media_service.h"

namespace OHOS {
namespace Media {
class MockIMediaService : public IMediaService {
public:
    MockIMediaService() = default;
    ~MockIMediaService() override {};
    MOCK_METHOD(std::shared_ptr<IPlayerService>, CreatePlayerService, (), (override));
    MOCK_METHOD(int32_t, DestroyPlayerService, (std::shared_ptr<IPlayerService> player), (override));

#ifdef SUPPORT_RECORDER
    MOCK_METHOD(std::shared_ptr<IRecorderService>, CreateRecorderService, (), (override));
    MOCK_METHOD(int32_t, DestroyRecorderService, (std::shared_ptr<IRecorderService> recorder), (override));
    MOCK_METHOD(std::shared_ptr<IRecorderProfilesService>, CreateRecorderProfilesService, (), (override));
    MOCK_METHOD(int32_t,
        DestroyMediaProfileService, (std::shared_ptr<IRecorderProfilesService> recorderProfiles), (override));
#endif

#ifdef SUPPORT_TRANSCODER
    MOCK_METHOD(std::shared_ptr<ITransCoderService>, CreateTransCoderService, (), (override));
    MOCK_METHOD(int32_t, DestroyTransCoderService, (std::shared_ptr<ITransCoderService> transCoder), (override));
#endif

#ifdef SUPPORT_METADATA
    MOCK_METHOD(std::shared_ptr<IAVMetadataHelperService>, CreateAVMetadataHelperService, (), (override));
    MOCK_METHOD(int32_t,
        DestroyAVMetadataHelperService, (std::shared_ptr<IAVMetadataHelperService> avMetadataHelper), (override));
#endif

#ifdef SUPPORT_SCREEN_CAPTURE
    MOCK_METHOD(std::shared_ptr<IScreenCaptureService>, CreateScreenCaptureService, (), (override));
    MOCK_METHOD(int32_t,
        DestroyScreenCaptureService, (std::shared_ptr<IScreenCaptureService> screenCaptureHelper), (override));
    
    MOCK_METHOD(std::shared_ptr<IScreenCaptureMonitorService>, CreateScreenCaptureMonitorService, (), (override));
    MOCK_METHOD(int32_t, DestroyScreenCaptureMonitorService,
        (std::shared_ptr<IScreenCaptureMonitorService> screenCaptureMonitor), (override));
    
    MOCK_METHOD(std::shared_ptr<IScreenCaptureController>, CreateScreenCaptureControllerClient, (), (override));
    MOCK_METHOD(int32_t,
        DestroyScreenCaptureControllerClient, (std::shared_ptr<IScreenCaptureController> controller), (override));
#endif

#ifdef SUPPORT_LPP_AUDIO_STRAMER
    MOCK_METHOD(std::shared_ptr<ILppAudioStreamerService>, CreateLppAudioStreamerService, (), (override));
    MOCK_METHOD(int32_t,
        DestroyLppAudioStreamerService, (std::shared_ptr<ILppAudioStreamerService> lppAudioPlayer), (override));
#endif
 
#ifdef SUPPORT_LPP_VIDEO_STRAMER
    MOCK_METHOD(std::shared_ptr<ILppVideoStreamerService>, CreateLppVideoStreamerService, (), (override));
    MOCK_METHOD(int32_t,
        DestroyLppVideoStreamerService, (std::shared_ptr<ILppVideoStreamerService> lppAudioPlayer), (override));
#endif

    MOCK_METHOD(sptr<IStandardMonitorService>, GetMonitorProxy, (), (override));
    MOCK_METHOD(bool, ReleaseClientListener, (), (override));
    MOCK_METHOD(bool, CanKillMediaService, (), (override));
    MOCK_METHOD(std::vector<pid_t>, GetPlayerPids, (), (override));
    MOCK_METHOD(int32_t, ProxyForFreeze, (const std::set<int32_t>& pidList, bool isProxy), (override));
    MOCK_METHOD(int32_t, ResetAllProxy, (), (override));
};
} // namespace Media
} // namespace OHOS
#endif