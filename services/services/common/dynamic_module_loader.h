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

#ifndef DYNAMIC_MODULE_LOADER_H
#define DYNAMIC_MODULE_LOADER_H

#include <mutex>
#include <map>
#include <string>
#include <dlfcn.h>

namespace OHOS {
namespace Media {

enum class DynamicModule {
    SCREEN_CAPTURE,
};

class DynamicModuleLoader {
public:
    static DynamicModuleLoader &Instance();

    template <typename T> T GetFactory(DynamicModule module, const std::string &symbol);

    bool IsLoaded(DynamicModule module) const;
    static const char *ModuleName(DynamicModule module);

private:
    DynamicModuleLoader() = default;
    ~DynamicModuleLoader() = default;
    __attribute__((no_sanitize("cfi"))) int32_t DoLoad(DynamicModule module);
    void *GetFactoryRaw(DynamicModule module, const std::string &symbol);

    struct ModuleInfo {
        void *handle = nullptr;
        bool loaded = false;
        std::string fullPath;
    };

    mutable std::mutex mutex_;
    std::map<DynamicModule, ModuleInfo> modules_;

#if (defined(__aarch64__) || defined(__x86_64__))
    static constexpr const char *LIB_DIR = "/system/lib64";
#else
    static constexpr const char *LIB_DIR = "/system/lib";
#endif
    static constexpr const char *LIB_PREFIX = "libmedia_service_";
    static constexpr const char *LIB_SUFFIX = ".z.so";
};

template <typename T> T DynamicModuleLoader::GetFactory(DynamicModule module, const std::string &symbol)
{
    void *raw = GetFactoryRaw(module, symbol);
    return reinterpret_cast<T>(raw);
}

} // namespace Media
} // namespace OHOS
#endif // DYNAMIC_MODULE_LOADER_H
