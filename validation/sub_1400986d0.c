__int64 sub_1400F3600();
extern __int64 off_140119260;

__int64 __fastcall sub_1400986D0(__int64 *a1, int a2) {
    __int64 v5;
    __int64 v7;
    __int64 v9;
    __int64 *dst;
    __int64 v6;
    __int64 result;
    __int64 v4;
    __int64 v8;
    __int64 v2;
    __int64 v10;

    v5 = a1[2];
    v7 = a1[7];
    v9 = v7 + 16;
    v7 += 20;
    if (v7 >= v9) {
        if (v7 <= v5) {
            dst = *(a1 + 8);
            *(dst + v9) = a2;
            a1[27] = a2;
            return (__int64)dst;
        }
    }
    v6 = &off_140119260;
    sub_1400F3600(v9, v7, v5, v6);
    result = v10;
    a2 = a1[28];
    *(a1 + result*8 + 80) = 0;
    v4 = a1[2];
    v8 = a1[7];
    a2 = v8 + result*8;
    a2 += 120;
    if (a2 <= v4) {
        v2 = v8 + result*8;
        v2 += 112;
        result = v2 + 4;
        if (v2 > -5) JUMPOUT(0x140098782);
        if (result > v4) JUMPOUT(0x140098782);
        a1 = *(a1 + 8);
        *(a1 + v2) = 0;
        if (a2 < result) JUMPOUT(0x140098794);
        *(a1 + result) = 0;
    }
    return result;
}