// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400B0320(struct Struct_1_t *a1, size_t a2, __int64 a3) {
    __int64 v11;
    __int64 v2;
    __int64 *dst;
    __int64 *src;
    __int64 result;
    __int64 v12;
    __int64 i;
    __int64 v4;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v10;

    v11 = ((__int64 *)a1)[2];
    if (v11 != 0) {
        v2 = a2;
        dst = (__int64 *)a1;
        src = a1->field_8;
        result = a3;
        result <<= 4;
        v12 = 0;
        i = 0;
        do {
            v4 =  + i*4;
            v4 += i;
            a1 = src + v4*8;
            a2 = *(src + v4*8 + 32);
            v4 = *(src + v4*8 + 24);
            v4 += a2;
            v5 = result;
            v6 = v2;
            while (v5 != 0) {
                v7 = v6;
                v6 += 16;
                v5 -= 16;
                ++i;
                if (a1->field_0 != 0) {
                    v10 = a1->field_8;
                    off_140108030(a1, a2, v4, v5);
                    off_140108038(result, 0, v10);
                }
                v12 = 1;
                if (i != v11) JUMPOUT(0x1400b03ed);
                v11 -= v12;
                *(dst + 16) = v11;
                return v11;
            }
            ++i;
        } while (i != v11);
        return i;
    }
    return result;
}