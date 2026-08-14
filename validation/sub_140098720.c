__int64 sub_1400F3600();
extern __int64 off_1401192C0;
extern __int64 off_1401192A8;

__int64 __fastcall sub_140098720(__int64 *a1, int a2) {
    __int64 result;
    __int64 v5;
    __int64 v6;
    __int64 v11;
    __int64 v7;
    __int64 v4;
    __int64 v9;
    __int64 v2;
    __int64 v3;
    __int64 v8;
    __int64 v10;

    result = v10;
    a2 = a1[28];
    *(a1 + result*8 + 80) = 0;
    v5 = a1[2];
    v6 = a1[7];
    v11 = v6 + result*8;
    v11 += 120;
    if (v11 <= v5) {
        v7 = v6 + result*8;
        v7 += 112;
        result = v7 + 4;
        if (v7 <= -5) {
            if (result > v5) {
                v4 = &off_1401192C0;
                sub_1400F3600(v7, result, v5, v4);
            } else {
                a1 = *(a1 + 8);
                *(a1 + v7) = 0;
                if (v11 >= result) {
                    *(a1 + result) = 0;
                    return (__int64)a1;
                }
            }
            v9 = &off_1401192A8;
            sub_1400F3600(result, v11, v5, v9);
            result = v5;
            v7 = a2;
            a1[15] = a2;
            a1[15] = v5;
            v2 = a1[2];
            a2 = a1[7];
            v3 = a2 + 160;
            if (v3 <= v2) {
                v8 = a2 + 152;
                a2 += 156;
                if (v8 > -5) JUMPOUT(0x140098805);
                if (a2 > v2) JUMPOUT(0x140098805);
                a1 = *(a1 + 8);
                *(a1 + v8) = v7;
                if (v3 < a2) JUMPOUT(0x140098814);
                *(a1 + a2) = result;
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return result;
}