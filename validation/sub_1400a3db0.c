// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 6 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[4];
    __int64 field_4; // offset 4
    int field_C; // offset 12
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3340();
__int64 sub_1400F37D0();
__int64 sub_1400A403A();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;

__int64 __fastcall sub_1400A3DB0(size_t *a1, size_t *a2) {
    __int64 __rdx_rax;
    int v_24;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    __int64 v_78;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v7;
    __int64 *dst2;
    __int64 v8;
    __int64 *result;
    __int64 v9;
    __int64 v11;
    __int64 *dst3;
    __int64 v6;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    dst = *a2;
    v7 = *(dst + 186);
    sub_14002EDF0(0, 288);
    if (result != 0) {
        dst2 = result;
        *result = 0;
        v8 = ptr->field_10;
        result = *(dst + 186);
        v9 = v8;
        v9 = ~v9;
        v9 += (__int64)result;
        *(dst2 + 186) = v9;
        a2 = *(dst + v8*4 + 8);
        result =  + v8*2;
        result += v8;
        a1 = *(dst + (__int64)(__int64)result*4 + 60);
        v_40 = (int)a1;
        result = *(dst + (__int64)(__int64)result*4 + 52);
        v_38 = (__int64)result;
        if (v9 < 12) {
            v_24 = (int)a2;
            result = dst + 8;
            v11 = dst + 52;
            a1 = dst2 + 8;
            a2 = result + v8*4;
            a2 += 4;
            v9 <<= 2;
            sub_1400F27F0(a1, a2, v9);
            a1 = dst2 + 52;
            result =  + v8*2 + 3;
            result += v8;
            a2 =  + (__int64)(__int64)result*4;
            a2 += v11;
            dst3 = v9 + v9*2;
            sub_1400F27F0(a1, a2, dst3);
            *(dst + 186) = v8;
            result = (__int64 *)v_38;
            v_28 = (__int64)result;
            result = (__int64 *)v_40;
            v_30 = (__int64)result;
            v9 = *(dst2 + 186);
            dst3 = v9 + 1;
            if (v9 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, dst3, 12, v6);
                sub_1400F3340(8, 288);
                v6 = &off_14011D898;
                sub_1400F3600(0, v9, 11, v6);
            } else {
                v7 -= v8;
                if (v7 == dst3) {
                    a1 = (size_t *)dst2;
                    a1 += 192;
                    a2 = dst + v8*8;
                    a2 += 200;
                    dst3 = (__int64 *)((__int64)(__int64)dst3 << 3);
                    sub_1400F27F0(a1, a2, dst3);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    dst3 = *(dst2 + (__int64)(__int64)a2*8 + 192);
                    *dst3 = dst2;
                    *(dst3 + 184) = a2;
                    while (a2 < v9) {
                    }
                    a1 = (size_t *)v_30;
                    ptr2->field_C = a1;
                    a1 = (size_t *)v_28;
                    ptr2->field_4 = a1;
                    ptr2->field_10 = dst;
                    ptr2->field_18 = result;
                    a1 = (size_t *)v_24;
                    *(__int64 *)ptr2 = (__int64)(a1);
                    ptr2->field_20 = dst2;
                    ptr2->field_28 = result;
                    return (__int64)a1;
                }
            }
            a1 = &off_14011D858;
            dst3 = &off_14011D880;
            sub_1400F37D0(a1, 40, dst3);
            ptr2 = (struct Struct_2_t *)a2;
            v_38 = (__int64)a1;
            result = 0x4000000000000000;
            a2 = 0;
            result = __rdx_rax / (__int64)ptr2; a2 = __rdx_rax % (__int64)ptr2; /* unsigned */;
            result += 1;
            v_78 = (__int64)result;
            result = (__int64 *)ptr2;
            if (ptr2 >= 0x1001) JUMPOUT(0x1400a4010);
            result = (__int64 *)((__int64)(__int64)result >> 1);
            a1 = (size_t *)ptr2;
            a1 = (size_t *)((__int64)a1 - (__int64)result);
            result = 64;
            if (a1 < 64) result = a1;
            v_48 = (__int64)result;
            return sub_1400A403A();
        }
        return v_48;
    }
    return (__int64)result;
}