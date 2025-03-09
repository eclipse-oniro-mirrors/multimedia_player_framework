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

#ifndef AUDIO_HAPTIC_TOOLS_H
#define AUDIO_HAPTIC_TOOLS_H

#include <string>
#include <map>
#include <vector>
#include <unordered_map>


namespace OHOS {
namespace Media {
template<typename T>
class ObjectRefMap {
public:
    static std::mutex allObjLock;
    static std::map<T*, uint32_t> refMap;
    static void Insert(T *obj);
    static void Erase(T *obj);
    static T *IncreaseRef(T *obj);
    static void DecreaseRef(T *obj);

    explicit ObjectRefMap(T *obj);
    ~ObjectRefMap();
    T *GetPtr();

private:
    T *obj_ = nullptr;
};

template <typename T>
std::mutex ObjectRefMap<T>::allObjLock;

template <typename T>
std::map<T *, uint32_t> ObjectRefMap<T>::refMap;

template <typename T>
void ObjectRefMap<T>::Insert(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    refMap[obj] = 1;
}

template <typename T>
void ObjectRefMap<T>::Erase(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    auto it = refMap.find(obj);
    if (it != refMap.end()) {
        refMap.erase(it);
    }
}

template <typename T>
T *ObjectRefMap<T>::IncreaseRef(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    if (refMap.count(obj)) {
        refMap[obj]++;
        return obj;
    } else {
        return nullptr;
    }
}

template <typename T>
void ObjectRefMap<T>::DecreaseRef(T *obj)
{
    std::lock_guard<std::mutex> lock(allObjLock);
    if (refMap.count(obj) && --refMap[obj] == 0) {
        refMap.erase(obj);
        delete obj;
        obj = nullptr;
    }
}

template <typename T>
ObjectRefMap<T>::ObjectRefMap(T *obj)
{
    if (obj != nullptr) {
        obj_ = ObjectRefMap::IncreaseRef(obj);
    }
}

template <typename T>
ObjectRefMap<T>::~ObjectRefMap()
{
    if (obj_ != nullptr) {
        ObjectRefMap::DecreaseRef(obj_);
    }
}

template <typename T>
T *ObjectRefMap<T>::GetPtr()
{
    return obj_;
}
} // namespace Media
} // namespace OHOS
#endif // AUDIO_HAPTIC_TOOLS_H
