// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140064210();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3B80();
extern __int64 off_140116D28;
extern __int64 off_140116C89;
extern __int64 off_140115EA0;
extern __int64 off_1401159D0;

__int64 __fastcall sub_140064FE0(int *a1, size_t *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int v_20;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_4a;
    int v_58;
    int v_60;
    int v_68;
    int v_78;
    char *str;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 v10;
    __int64 v11;
    __int64 *dst;
    __int64 v2;
    __m128i xmm0;
    __int64 i;
    __int64 result;
    __int64 v9;
    __int64 v6;
    int v7;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    v10 = arg_10;
    v11 = arg_18;
    v_30 = 1;
    v_38 = 2;
    v_40 = 2;
    v_48 = 0x3000;
    v_4a = 57;
    a1 = rsp + 80;
    a2 = rsp + 48;
    sub_140064210(a1, a2, ptr2);
    dst = (__int64 *)str;
    a1 = (int *)v_58;
    a2 = (size_t *)v_60;
    if (dst != 3) {
        v2 = v_78;
        ptr->field_28 = v2;
        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
        *(__int64 *)ptr = (__int64)(dst);
        ptr->field_8 = a1;
        ptr->field_10 = a2;
    } else {
        if (a2 == 1) {
            i = *a1;
            a2 = 1;
            if (i != 43) {
                result = 1;
                if (i != 45) {
                    a2 = 0;
                    i = 0;
                    v2 = *(__int64 *)((__int64)a1 + (__int64)a2);
                    v2 += 0xFFFFFFD0;
                    while (v2 <= 9) {
                        i += i;
                        i += i*4;
                        v2 += i;
                        ++a2;
                        if (v2 >= 60) {
                            ptr2->field_10 = v10;
                            ptr2->field_18 = v11;
                            sub_14002EDF0(0, 48, v2);
                            if (dst == 0) {
                                sub_1400F3340(8, 48, i, 10);
                                a2 = 1;
                                do {
                                    str = (char *)a2;
                                    v9 = &off_140116D28;
                                    v_20 = v9;
                                    a1 = &off_140116C89;
                                    v6 = &off_140115EA0;
                                    sub_1400F3B80(a1, 22, str, v6);
                                    a2 = 0;
                                } while (true);
                            } else {
                                a1 = 0x8000000000000001;
                                *dst = a1;
                                *(dst + 8) = v2;
                                *(__int64 *)ptr = (__int64)(1);
                                ptr->field_8 = 0;
                                ptr->field_10 = 8;
                                ptr->field_18 = 0;
                                ptr->field_20 = dst;
                                dst = &off_1401159D0;
                                ptr->field_28 = dst;
                            }
                        } else {
                            ptr->field_8 = v2;
                            *(__int64 *)ptr = (__int64)(3);
                        }
                        return (__int64)dst;
                    }
                    return (__int64)dst;
                } else {
                }
            }
        } else {
            if (a2 != 0) {
                if (*a1 != 43) {
                    result = 2;
                    if (a2 >= 3) {
                        i = 0;
                        v2 = 0;
                        while (a2 != i) {
                            v7 = *(a1 + i);
                            v7 += 0xFFFFFFD0;
                            result = v2;
                            dst = (__int64 *)((__int64)(__int64)(__int64)dst * v6); /* unsigned; high half in a2 */;
                            if (!((0 /* overflow check on (v7 + 0xFFFFFFD0) */))) {
                                if (v7 <= 9) {
                                    v2 = result;
                                    ++i;
                                    v2 += v7;
                                    a2 = 2;
                                    return (__int64)a2;
                                }
                            }
                            a2 = 0;
                            ++a2;
                            return (__int64)a2;
                        }
                    } else {
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                } else {
                    ++a1;
                    dst = a2 - 1;
                    a2 = (size_t *)dst;
                    if ((a2 < 4)) {
                        return (__int64)a2;
                    } else {
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                }
                return (__int64)a2;
            }
            return (__int64)a2;
        }
        return (__int64)a2;
    }
    return result;
}