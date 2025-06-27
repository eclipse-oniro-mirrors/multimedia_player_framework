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

#ifndef I_ENGINE_FACTORY_H
#define I_ENGINE_FACTORY_H

#include <string>
#include <memory>
#ifdef SUPPORT_PLAYER
#include "i_player_engine.h"
#endif
#ifdef SUPPORT_RECORDER
#include "i_recorder_engine.h"
#endif
#ifdef SUPPORT_METADATA
#include "i_avmetadatahelper_engine.h"
#endif
#ifdef SUPPORT_TRANSCODER
#include "i_transcoder_engine.h"
#include "i_transcoder_engine.h"
#endif

#ifdef SUPPORT_LPP
#include "i_lpp_video_streamer.h"
#include "i_lpp_audio_streamer.h"
#endif
namespace OHOS {
namespace Media {
class IEngineFactory {
public:
    enum class Scene {
        SCENE_PLAYBACK,
        SCENE_AVMETADATA,
        SCENE_RECORDER,
        SCENE_AVCODEC,
        SCENE_AVCODECLIST,
        SCENE_TRANSCODER,
    };

    virtual ~IEngineFactory() = default;
    virtual int32_t Score(Scene scene, const int32_t& appUid, const std::string &uri = "")
    {
        (void)scene;
        (void)appUid;
        (void)uri;
        return 0;
    }

#ifdef SUPPORT_PLAYER
    virtual std::unique_ptr<IPlayerEngine> CreatePlayerEngine(int32_t uid = 0, int32_t pid = 0, uint32_t tokenId = 0)
    {
        (void)uid;
        (void)pid;
        (void)tokenId;
        return nullptr;
    }
#endif

#ifdef SUPPORT_RECORDER
    virtual std::unique_ptr<IRecorderEngine> CreateRecorderEngine(int32_t appUid, int32_t appPid, uint32_t appTokenId,
        uint64_t appFullTokenId)
    {
        (void)appUid;
        (void)appPid;
        (void)appTokenId;
        (void)appFullTokenId;
        return nullptr;
    }
#endif

#ifdef SUPPORT_METADATA
    virtual std::unique_ptr<IAVMetadataHelperEngine> CreateAVMetadataHelperEngine(int32_t uid = 0, int32_t pid = 0,
        uint32_t tokenId = 0, std::string appName = "")
    {
        return nullptr;
    }
#endif

#ifdef SUPPORT_TRANSCODER
    virtual std::unique_ptr<ITransCoderEngine> CreateTransCoderEngine(int32_t appUid, int32_t appPid,
        uint32_t appTokenId, uint64_t appFullTokenId)
    {
        (void)appUid;
        (void)appPid;
        (void)appTokenId;
        (void)appFullTokenId;
        return nullptr;
    }
#endif

#ifdef SUPPORT_LPP
    virtual std::shared_ptr<ILppVideoStreamerEngine> CreateLppVideoStreamerEngine(int32_t appUid, int32_t appPid,
        uint32_t tokenId)
    {
        (void)appUid;
        (void)appPid;
        (void)tokenId;
        return nullptr;
    }

    virtual std::shared_ptr<ILppAudioStreamerEngine> CreateLppAudioStreamerEngine(int32_t appUid, int32_t appPid,
        uint32_t tokenId)
    {
        (void)appUid;
        (void)appPid;
        (void)tokenId;
        return nullptr;
    }
#endif

protected:
    static constexpr int32_t MAX_SCORE = 100;
    static constexpr int32_t MIN_SCORE = 0;
};
} // namespace Media
} // namespace OHOS
#endif