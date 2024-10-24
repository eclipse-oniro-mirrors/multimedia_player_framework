/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "math_utils.h"

namespace OHOS {
namespace Media {
static Mat3x3 BasisToPoints(Vec2 a, Vec2 b, Vec2 c, Vec2 d)
{
    Mat3x3 m = Mat3x3(Vec3(a, 1.0f), Vec3(b, 1.0f), Vec3(c, 1.0f));
    Vec3 v(d, 1.0f);
    v = MathUtils::Inversed(m) * v;
    Mat3x3 n = Mat3x3(v.x, 0.0, 0.0, 0.0, v.y, 0.0, 0.0, 0.0, v.z);
    return m * n;
}

Mat3x3 MathUtils::CalProj2D(const Vec2& sa, const Vec2& sb, const Vec2& sc, const Vec2& sd, const Vec2& da, const Vec2& db, const Vec2& dc, const Vec2& dd)
{
    return BasisToPoints(da, db, dc, dd) * MathUtils::Inversed(BasisToPoints(sa, sb, sc, sd));
}

Mat3x3 MathUtils::CalProj2D(const Mat4x4& mvp)
{
    Vec4 a(-1.0, -1.0, 0.0, 1.0), b(1.0, -1.0, 0.0, 1.0), c(-1.0, 1.0, 0.0, 1.0), d(1.0, 1.0, 0.0, 1.0);
    a = mvp * a;
    b = mvp * b;
    c = mvp * c;
    d = mvp * d;
    return BasisToPoints(Vec2(0.0, 0.0), Vec2(1.0, 0.0), Vec2(1.0, 1.0), Vec2(0.0, 1.0)) * 
        MathUtils::Inversed(BasisToPoints((Vec2(a.x, a.y) / a.w +1.0f) / 2.0f, (Vec2(b.x, b.y) / b.w + 1.0f) / 2.0f, 
        (Vec2(d.x, d.y) / d.w + 1.0f) / 2.0f, (Vec2(c.x, c.y) / c.w + 1.0f) / 2.0f));
}

Mat3x3 MathUtils::CalProj2DInv(const Mat4x4& mvp)
{
    float x = 1.0, y = 1.0;
    Vec4 a(-x, -y, 0.0, 1.0), b(x, -y, 0.0, 1.0), c(-x, y, 0.0, 1.0), d(x, y, 0.0, 1.0);
    a = mvp * a;
    b = mvp * b;
    c = mvp * c;
    d = mvp * d;
    return MathUtils::Inversed(BasisToPoints(Vec2(0.0, 0.0), Vec2(1.0, 0.0), Vec2(1.0, 1.0), Vec2(0.0, 1.0)) *
        MathUtils::Inversed(BasisToPoints((Vec2(a.x, a.y) / a.w + 1.0f) / 2.0f, (Vec2(b.x, b.y) / b.w + 1.0f) / 2.0f,
        (Vec2(d.x, d.y) / d.w + 1.0f) / 2.0f, (Vec2(c.x, c.y) / c.w + 1.0f) / 2.0f)));
}

bool MathUtils::isPointInRect(const Vec2& p, const Vec2& rectP0, const Vec2& rectP1, const Vec2& rectP2,
    const Vec2& rectP3)
{
    Vec2 v0 = rectP0 - rectP3;
    Vec2 v1 = p - rectP3;
    if(v0.x * v1.y - v1.x * v0.y < 0.0) {
        return false;
    }
    v0 = rectP1 - rectP0;
    v1 = p - rectP0;
    if(v0.x * v1.y - v1.x * v0.y < 0.0) {
        return false;
    }
    v0 = rectP2 - rectP1;
    v1 = p - rectP1;
    if(v0.x * v1.y - v1.x * v0.y < 0.0) {
        return false;
    }
    v0 = rectP3 - rectP2;
    v1 = p - rectP2;
    if(v0.x * v1.y - v1.x * v0.y < 0.0) {
        return false;
    }
    return true;
}

// rect的顶点需要按照逆时针顺序输入
bool MathUtils::IsSegmentsCross(const Vec2& s0, const Vec2& e0, const Vec2& s1, const Vec2& e1)
{
    if(std::max(s0.x, e0.x) < std::min(s1.x, e1.x) || std::max(s0.y, e0.y) < std::min(s1.y, e1.y) ||
       std::min(s0.x, e0.x) > std::max(s1.x, e1.x) || std::min(s0.y, e0.y) > std::max(s1.y, e1.y)) {
        return false;
    }
    if(((s1.x - s0.x) * (s1.y - e1.y) - (s1.y - s0.y) * (s1.x - e1.x)) * 
       ((s1.x - s0.x) * (s1.y - e1.y) - (s1.y - s0.y) * (s1.x - e1.x)) <=
       0 &&
       ((s0.x - s1.x) * (s0.y - e0.y) - (s0.y - s1.y) * (s0.x - e0.x)) *
       ((s0.x - s1.x) * (s0.y - e0.y) - (s0.y - s1.y) * (s0.x - e0.x)) <=
       0) {
        return true;
    }
    return false;
}

double MathUtils::GetTriangleArea(const Vec2& p0, const Vec2& p1, const Vec2& p2)
{
    return std::abs((p2.x - p1.x) * (p0.y - p1.y) - (p2.y - p1.y) * (p0.x - p1.x));
}

void MathUtils::GetSegmentsCrossPoints(const Vec2& s0, const Vec2& e0, const Vec2& s1, const Vec2& e1,
     std::vector<Vec2>& result)
{
    if(!IsSegmentsCross(s0, e0, s1, e1)) {
        return;
    }
    double a0 = GetTriangleArea(s1, s0, e0), a1 = GetTriangleArea(e1, s0, e0);
    if(!islessgreater(a0, 0.0)) {
        if(!islessgreater(a1, 0.0)) {
            std::vector<Vec2> allVec{ s0, e0, s1, e1 };
            std::sort(allVec.begin(), allVec.end(), [](const Vec2& a, const Vec2& b) {
                if(islessgreater(a.x, b.x))
                    return a.x <= b.x;
                else
                    return a.y <= b.y;
            });
            result.emplace_back(allVec[1]);
            if(islessgreater(allVec[1].x, allVec[2].x) || islessgreater(allVec[1].y, allVec[2].y)) {
                result.emplace_back(allVec[2]);
            }
        } else {
            result.emplace_back(s1);
        }
    } else if(!islessgreater(a1, 0.0)) {
        result.emplace_back(e1);
    } else {
        double k = a0 / a1;
        result.emplace_back((s1.x + k * e1.x) / (1 + k), (s1.y + k * e1.y) / (1 + k));
    }
}

std::vector<Vec2> MathUtils::GetTwoRectCrossAreaPoints(const Vec2& a0, const Vec2& a1, const Vec2& a2, const Vec2& a3,
    const Vec2& b0, const Vec2& b1, const Vec2& b2, const Vec2& b3)
{
    bool isInRect0 = isPointInRect(a0, b0, b1, b2, b3);
    bool isInRect1 = isPointInRect(a1, b0, b1, b2, b3);
    bool isInRect2 = isPointInRect(a2, b0, b1, b2, b3);
    bool isInRect3 = isPointInRect(a3, b0, b1, b2, b3);
    if(isInRect0 && isInRect1 && isInRect2 && isInRect3) {
        return { a0, a1, a2, a3};
    }
    bool isInRect4 = isPointInRect(b0, a0, a1, a2, a3);
    bool isInRect5 = isPointInRect(b1, a0, a1, a2, a3);
    bool isInRect6 = isPointInRect(b2, a0, a1, a2, a3);
    bool isInRect7 = isPointInRect(b3, a0, a1, a2, a3);
    if(isInRect4 && isInRect5 && isInRect6 && isInRect7) {
        return { b0, b1, b2, b3};
    }
    std::vector<Vec2> result;
    if(isInRect0)
       result.emplace_back(a0);
    if(isInRect1)
       result.emplace_back(a1);
    if(isInRect2)
       result.emplace_back(a2);
    if(isInRect3)
       result.emplace_back(a3);
    if(isInRect4)
       result.emplace_back(b0);
    if(isInRect5)
       result.emplace_back(b1);
    if(isInRect6)
       result.emplace_back(b2);
    if(isInRect7)
       result.emplace_back(b3);
    GetSegmentsCrossPoints(a0, a1, b0, b1, result);
    GetSegmentsCrossPoints(a0, a1, b1, b2, result);
    GetSegmentsCrossPoints(a0, a1, b2, b3, result);
    GetSegmentsCrossPoints(a0, a1, b3, b0, result);
    GetSegmentsCrossPoints(a1, a2, b0, b1, result);
    GetSegmentsCrossPoints(a1, a2, b1, b2, result);
    GetSegmentsCrossPoints(a1, a2, b2, b3, result);
    GetSegmentsCrossPoints(a1, a2, b3, b0, result);
    GetSegmentsCrossPoints(a2, a3, b0, b1, result);
    GetSegmentsCrossPoints(a2, a3, b1, b2, result);
    GetSegmentsCrossPoints(a2, a3, b2, b3, result);
    GetSegmentsCrossPoints(a2, a3, b3, b0, result);
    GetSegmentsCrossPoints(a3, a0, b0, b1, result);
    GetSegmentsCrossPoints(a3, a0, b1, b2, result);
    GetSegmentsCrossPoints(a3, a0, b2, b3, result);
    GetSegmentsCrossPoints(a3, a0, b3, b0, result);
    return result;
}
}
}