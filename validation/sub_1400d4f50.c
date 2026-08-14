// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3510();
__int64 sub_1400F2D20();

__int64 __fastcall sub_1400D4F50(struct Struct_1_t *a1, int a2, int a3, int a4) {
    int v_20;
    __int64 result;
    __int64 v5;
    __int64 v4;
    struct Struct_2_t *ptr;
    __int64 i;
    int v10;
    __int64 v8;
    __int64 *dst;
    __int64 *dst2;
    __int64 *dst3;

    result = (a4 == 0) ? 1 : 0;
    v5 = (a3 != 5) ? 1 : 0;
    if ((v5 & result) != 0) {
        a2 <<= 3;
        a2 |= a3;
        v4 = ((__int64 *)a1)[2];
        if (v4 == a1->field_0) {
            ptr = (struct Struct_2_t *)a1;
            i = a3;
            v10 = a2;
            sub_1400F3510(a1, a2, a3, a4);
        }
        v8 = v4 + 1;
        dst = a1->field_8;
        *(dst + v4) = a2;
        ((__int64 *)a1)[2] = (__int64)(v8);
        if (a3 == 4) {
            if (v8 == a1->field_0) {
                ptr = (struct Struct_2_t *)a1;
                sub_1400F3510(ptr, i, dst, v10);
                dst = ptr->field_8;
            }
            *(dst + v4 + 1) = 36;
            v4 += 2;
            ((__int64 *)a1)[2] = (__int64)(v4);
        }
    } else {
        result = a4;
        a2 <<= 3;
        a2 |= a3;
        if (a4 == a4) {
            a2 |= 64;
            dst = a1->field_0;
            v4 = ((__int64 *)a1)[2];
            if (v4 == dst) {
                ptr = (struct Struct_2_t *)a1;
                v10 = a4;
                dst = (__int64 *)a3;
                i = a2;
                sub_1400F3510(ptr);
                dst = ptr->field_0;
            }
            i = v4 + 1;
            dst2 = a1->field_8;
            *(dst2 + v4) = a2;
            ((__int64 *)a1)[2] = (__int64)(i);
            if (a3 == 4) {
                if (i == dst) {
                    ptr = (struct Struct_2_t *)a1;
                    i = a4;
                    sub_1400F3510(ptr, a2, a3, i);
                    a4 = i;
                    dst = ptr->field_0;
                    dst2 = ptr->field_8;
                }
                *(dst2 + v4 + 1) = 36;
                v4 += 2;
                ((__int64 *)a1)[2] = (__int64)(v4);
                i = v4;
            }
            if (i == dst) {
                ptr = (struct Struct_2_t *)a1;
                v4 = a4;
                sub_1400F3510(ptr, i, dst, v10);
                dst2 = ptr->field_8;
            }
            *(dst2 + i) = a4;
            ++i;
            ((__int64 *)a1)[2] = (__int64)(i);
        } else {
            a2 |= 128;
            v5 = a1->field_0;
            v4 = ((__int64 *)a1)[2];
            if (v4 == v5) {
                ptr = (struct Struct_2_t *)a1;
                dst = (__int64 *)a3;
                i = a2;
                sub_1400F3510(ptr, a4, i);
                v5 = ptr->field_0;
            }
            dst = v4 + 1;
            dst3 = a1->field_8;
            *(dst3 + v4) = a2;
            ((__int64 *)a1)[2] = (__int64)(dst);
            if (a3 == 4) {
                if (dst == v5) {
                    ptr = (struct Struct_2_t *)a1;
                    i = a4;
                    sub_1400F3510(ptr, a2, a3, v4);
                    v5 = ptr->field_0;
                    dst3 = ptr->field_8;
                }
                *(dst3 + v4 + 1) = 36;
                v4 += 2;
                ((__int64 *)a1)[2] = (__int64)(v4);
                dst = (__int64 *)v4;
            }
            v5 -= (__int64)dst;
            if (v5 <= 3) {
                v_20 = 1;
                v4 = a4;
                ptr = (struct Struct_2_t *)a1;
                sub_1400F2D20(ptr, dst, 4, 1);
                a4 = v4;
                a1 = (struct Struct_1_t *)ptr;
                dst3 = ptr->field_8;
                dst = ptr->field_10;
            }
            *(__int64 *)((__int64)dst3 + (__int64)dst) = a4;
            dst += 4;
            ((__int64 *)a1)[2] = (__int64)(dst);
        }
    }
    return result;
}