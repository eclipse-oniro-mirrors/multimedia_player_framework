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

#ifndef SYSTEM_SOUND_PLAYER_H
#define SYSTEM_SOUND_PLAYER_H

#include <memory>
#include <mutex>

#include "system_sound_manager.h"

namespace OHOS {
namespace Media {
const int32_t SSP_SUCCESS = 0;
const int32_t SSP_ERROR = -1;
const int32_t ERRCODE_NO_MEMORY = 5400101;
const int32_t ERRCODE_IO_ERROR = 5400103;
const int32_t ERRCODE_SYSTEM_ERROR = 5400105;
const int32_t ERRCODE_INVALID_PARAM = 5400108;
const std::string ERRCODE_NO_MEMORY_INFO = "allocate memory failed";
const std::string ERRCODE_IO_ERROR_INFO = "I/O error";
const std::string ERRCODE_SYSTEM_ERROR_INFO = "system error";
const std::string ERRCODE_INVALID_PARAM_INFO = "invalid parameter";

class SystemSoundPlayer {
public:
    virtual ~SystemSoundPlayer() = default;

    /**
     * @brief Load system sound.
     *
     * @param systemSoundType Indicates the system sound type id.
     * @return Returns SSP_SUCCESS if successful;
     * returns an error code otherwise.
     * @since 23
     */
    virtual int32_t Load(SystemSoundType systemSoundType) = 0;

    /**
     * @brief Play system sound.
     *
     * @param systemSoundType Indicates the system sound type id.
     * @return Returns SSP_SUCCESS if successful;
     * returns an error code otherwise.
     * @since 23
     */
    virtual int32_t Play(SystemSoundType systemSoundType) = 0;

    /**
     * @brief Unload system sound.
     *
     * @param systemSoundType Indicates the system sound type id.
     * @return Returns SSP_SUCCESS if successful;
     * returns an error code otherwise.
     * @since 23
     */
    virtual int32_t Unload(SystemSoundType systemSoundType) = 0;

    /**
     * @brief Release system sound.
     *
     * @return Returns SSP_SUCCESS if successful;
     * returns an error code otherwise.
     * @since 23
     */
    virtual int32_t Release() = 0;
};

class __attribute__((visibility("default"))) SystemSoundPlayerFactory {
public:
    static std::shared_ptr<SystemSoundPlayer> CreateSystemSoundPlayer();

private:
    static std::mutex g_systemSoundPlayerMutex;
    SystemSoundPlayerFactory() = default;
    ~SystemSoundPlayerFactory() = default;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_TONE_PLAYER_H
