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

#ifndef MEDIASERVERMANAGER_FUZZER
#define MEDIASERVERMANAGER_FUZZER

#include <cstddef>
#include <cstdint>

#define FUZZ_PROJECT_NAME "mediaservermanager_fuzzer"

namespace OHOS {
namespace Media {
class MediaServerManagerFuzzer {
public:
    MediaServerManagerFuzzer();
    ~MediaServerManagerFuzzer();
    void FuzzMediaServerManagerResetAllProxy(uint8_t *data, size_t size);
    void FuzzMediaServerManagerAll(uint8_t *data, size_t size);
    void FuzzMediaServerManagerFreezeStubForPids(uint8_t *data, size_t size);
    void FuzzMediaServerManagerCreateRecorder(uint8_t *data, size_t size);
    void FuzzMediaServerManagerMonitorAndCodec(uint8_t *data, size_t size);
    void FuzzCanKillMediaService(uint8_t *data, size_t size);
    void FuzzSetClearCallBack(uint8_t *data, size_t size);
    void FuzzReportAppMemoryUsage(uint8_t *data, size_t size);
    void FuzzGetPlayerPids(uint8_t *data, size_t size);
    void FuzzDestroyDumperForPid(uint8_t *data, size_t size);
    inline void CreateAndDestroyStub(MediaServerManager &mgr, MediaServerManager::StubType type);
};
} // namespace Media
void FuzzTestMediaServerManager(uint8_t *data, size_t size);
} // namespace OHOS
#endif