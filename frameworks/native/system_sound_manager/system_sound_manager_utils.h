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
#ifndef SYSTEM_SOUND_MANAGER_UTILS_H
#define SYSTEM_SOUND_MANAGER_UTILS_H

#include <array>
#include "datashare_helper.h"
#include "uri.h"
#include "want.h"
#include "access_token.h"
#include <iostream>

#include "audio_system_manager.h"
#include "system_sound_manager.h"

namespace OHOS {
namespace Media {

class SystemSoundManagerUtils {
public:
    static int32_t GetCurrentUserId();
    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId);
    static void CreateDataShareHelper(int32_t systemAbilityId,
        bool &isProxy, std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper);
    static bool VerifyCustomPath(const std::string &audioUri);
    static bool IdExists(const std::string &ids, int32_t id);
    static bool CheckCurrentUser();
    static bool GetScannerFirstParameter(const char* key, int32_t maxSize);
    static int32_t GetTypeForSystemSoundUri(const std::string &audioUri);
    static std::string GetErrorReason(const int32_t &errorCode);
    static std::string GetTonePlaybackErrorReason(const int32_t &errorCode);
private:
    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelperUri(int32_t systemAbilityId);
};

class __attribute__((visibility("default"))) MediaTrace : public NoCopyable {
public:
    explicit MediaTrace(const std::string &funcName);
    static void TraceBegin(const std::string &funcName, int32_t taskId);
    static void TraceEnd(const std::string &funcName, int32_t taskId);
    static void CounterTrace(const std::string &varName, int32_t val);
    ~MediaTrace();
private:
    bool isSync_ = false;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_SOUND_MANAGER_UTILS_H