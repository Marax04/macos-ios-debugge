// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `i`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_4_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3326();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3B80();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011C458;
extern __int64 off_14011C440;

__int64 __fastcall sub_1400DAC20(int *a1, int *a2, int str, int a4) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 *dst;
    __int64 v2;
    __int64 *dst2;
    struct Struct_3_t *ptr;
    struct Struct_2_t *i;
    struct Struct_1_t *result;
    __int64 i2;
    __int64 *dst3;
    __int64 v8;
    __int64 v5;
    struct Struct_4_t *ptr2;

    dst = (__int64 *)a4;
    v2 = str;
    dst2 = (__int64 *)a2;
    ptr = (struct Struct_3_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        i = (struct Struct_2_t *)result;
        *(__int64 *)result = (__int64)(0x244C8D48);
        result->field_4 = 32;
        result = ptr->field_0;
        i2 = ptr->field_10;
        result -= i2;
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 5, 1);
            i2 = ptr->field_10;
        }
        dst3 = ptr->field_8;
        result = i->field_4;
        *(dst3 + i2 + 4) = result;
        result = i->field_0;
        *(dst3 + i2) = result;
        i2 += 5;
        ptr->field_10 = i2;
        off_140108030();
        off_140108038(result, 0, i);
        v8 = *dst2;
        result = v8 + 1;
        v_40 = (__int64)dst2;
        *dst2 = result;
        sub_14002EDF0(0, 8);
        if (result == 0) {
            sub_1400F3326(1, 8);
        } else {
            str = 8;
            v_30 = (__int64)result;
            *(__int64 *)result = (__int64)(0x8D48);
            v_38 = 2;
            a1 = rsp + 40;
            sub_1400D4F50(a1, 2, 4, dst);
            dst = (__int64 *)str;
            i = (struct Struct_2_t *)v_30;
            v5 = v_38;
            result = ptr->field_0;
            result -= i2;
            if (v5 > result) {
                v_20 = 1;
                sub_1400F2D20(ptr, i2, v5, 1);
                dst3 = ptr->field_8;
                i2 = ptr->field_10;
            }
            a1 = dst3 + i2;
            sub_1400F27F0(a1, i, v5);
            i2 += v5;
            ptr->field_10 = i2;
            if (dst != 0) {
                off_140108030();
                off_140108038(result, 0, i);
            }
            result = (struct Struct_1_t *)i2;
            result += 5;
            i = (struct Struct_2_t *)v_40;
            if ((result < 0)) {
                result = &off_14011B3E0;
                v_20 = (__int64)result;
                a1 = &off_14011B3C3;
                a4 = &off_14011D3F8;
                sub_1400F3B80(a1, 23, str, a4);
            } else {
                v2 -= (__int64)result;
                result = (struct Struct_1_t *)v2;
                if (v2 == v2) {
                    if (ptr->field_0 == i2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr, i2, 1, 1);
                        dst3 = ptr->field_8;
                        i2 = ptr->field_10;
                    }
                    *(dst3 + i2) = 232;
                    ++i2;
                    ptr->field_10 = i2;
                    result = ptr->field_0;
                    result -= i2;
                    if (result <= 3) {
                        v_20 = 1;
                        sub_1400F2D20(ptr, i2, 4, 1);
                        i2 = ptr->field_10;
                    }
                    result = ptr->field_8;
                    *(__int64 *)(result + i2) = (__int64)(v2);
                    i2 += 4;
                    ptr->field_10 = i2;
                    v8 += 3;
                    *(__int64 *)i = (__int64)(v8);
                    return v8;
                }
            }
            result = &off_14011C458;
            v_20 = (__int64)result;
            a1 = &off_14011C440;
            a4 = &off_14011D3F8;
            sub_1400F3B80(a1, 24, str, a4);
            v2 = str;
            dst3 = (__int64 *)a2;
            ptr = (struct Struct_3_t *)a1;
            sub_14002EDF0(0, 8);
            if (result == 0) JUMPOUT(0x1400db0d0);
            i = (struct Struct_2_t *)result;
            *(__int64 *)result = (__int64)(0x244C8D48);
            result->field_4 = 32;
            result = ptr->field_0;
            i2 = ptr->field_10;
            result -= i2;
            if (result <= 4) JUMPOUT(0x1400db015);
            dst = ptr->field_8;
            result = i->field_4;
            *(dst + i2 + 4) = result;
            result = i->field_0;
            *(dst + i2) = result;
            i2 += 5;
            ptr->field_10 = i2;
            off_140108030();
            off_140108038(result, 0, i);
            v8 = *dst3;
            result = v8 + 1;
            *dst3 = result;
            sub_14002EDF0(0, 3);
            if (result == 0) JUMPOUT(0x1400db03e);
            ptr2 = (struct Struct_4_t *)result;
            *(__int64 *)result = (__int64)(0x894C);
            result->field_2 = 226;
            result = ptr->field_0;
            result -= i2;
            if (result <= 2) JUMPOUT(0x1400db04d);
            result = ptr2->field_2;
            *(dst + i2 + 2) = result;
            result = ptr2->field_0;
            *(dst + i2) = result;
            i = i2 + 3;
            ptr->field_10 = i;
            off_140108030();
            off_140108038(result, 0, ptr2);
            i2 += 8;
            if ((i2 < 0)) JUMPOUT(0x1400db0df);
            v2 -= i2;
            result = (struct Struct_1_t *)v2;
            if (v2 != v2) JUMPOUT(0x1400db108);
            if (ptr->field_0 == i) JUMPOUT(0x1400db07a);
            *(__int64 *)((__int64)dst + (__int64)i) = 232;
            ++i;
            ptr->field_10 = i;
            result = ptr->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
            if (result <= 3) JUMPOUT(0x1400db0a7);
            result = ptr->field_8;
            *(__int64 *)((__int64)result + (__int64)i) = v2;
            i += 4;
            ptr->field_10 = i;
            v8 += 3;
            *dst3 = v8;
            return v8;
        }
        return v8;
    }
    return (__int64)result;
}