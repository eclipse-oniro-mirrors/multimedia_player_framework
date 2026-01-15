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

#ifndef LPP_PLAYER_SERVICE_STUB_H
#define LPP_PLAYER_SERVICE_STUB_H

#include "i_standard_lpp_audio_streamer_service.h"
#include "lpp_audio_streamer_server.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {
using PlayerStubFunc = std::function<int32_t(MessageParcel &, MessageParcel &)>;
class LppAudioStreamerServiceStub : public IRemoteStub<IStandardLppAudioStreamerService>, public NoCopyable {
public:
    static sptr<LppAudioStreamerServiceStub> Create();
    ~LppAudioStreamerServiceStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t Init(const std::string &mime) override;

    int32_t SetParameter(const Format &param) override;

    int32_t Configure(const Format &param) override;

    int32_t Prepare() override;

    int32_t Start() override;

    int32_t Pause() override;

    int32_t Resume() override;

    int32_t Flush() override;

    int32_t Stop() override;

    int32_t Reset() override;

    int32_t Release() override;

    int32_t SetVolume(float volume) override;

    int32_t SetLoudnessGain(const float loudnessGain) override;

    int32_t SetPlaybackSpeed(float speed) override;

    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;

    int32_t RegisterCallback() override;

    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;

    int32_t SetLppAudioStreamerCallback() override;

    std::string GetStreamerId() override;

    int32_t SetLppVideoStreamerId(const std::string videoStreamId) override;

    int32_t Init();
    void SetPlayerFuncs();
    void FillPlayerFuncPart1();

private:
    LppAudioStreamerServiceStub();
    std::mutex aServiceStubMutex_;

public:
    int32_t Init(MessageParcel &data, MessageParcel &reply);
    int32_t SetParameter(MessageParcel &data, MessageParcel &reply);
    int32_t Configure(MessageParcel &data, MessageParcel &reply);
    int32_t Prepare(MessageParcel &data, MessageParcel &reply);
    int32_t Start(MessageParcel &data, MessageParcel &reply);
    int32_t Pause(MessageParcel &data, MessageParcel &reply);
    int32_t Resume(MessageParcel &data, MessageParcel &reply);
    int32_t Flush(MessageParcel &data, MessageParcel &reply);
    int32_t Stop(MessageParcel &data, MessageParcel &reply);
    int32_t Reset(MessageParcel &data, MessageParcel &reply);
    int32_t Release(MessageParcel &data, MessageParcel &reply);
    int32_t SetVolume(MessageParcel &data, MessageParcel &reply);
    int32_t SetLoudnessGain(MessageParcel &data, MessageParcel &reply);
    int32_t SetPlaybackSpeed(MessageParcel &data, MessageParcel &reply);
    int32_t ReturnFrames(MessageParcel &data, MessageParcel &reply);
    int32_t RegisterCallback(MessageParcel &data, MessageParcel &reply);
    int32_t SetListenerObject(MessageParcel &data, MessageParcel &reply);
    int32_t SetLppAudioStreamerCallback(MessageParcel &data, MessageParcel &reply);
    int32_t SetLppVideoStreamerId(MessageParcel &data, MessageParcel &reply);
    int32_t GetStreamerId(MessageParcel &data, MessageParcel &reply);

    std::shared_ptr<ILppAudioStreamerService> lppAudioPlayerServer_ = nullptr;
    std::map<uint32_t, std::pair<std::string, PlayerStubFunc>> playerFuncs_;
    std::shared_ptr<AudioStreamerCallback> playerCallback_ = nullptr;
    sptr<LppDataPacket> framePacket_ = nullptr;
    TaskQueue taskQue_;
};
}  // namespace Media
}  // namespace OHOS
#endif  // PLAYER_SERVICE_STUB_H
