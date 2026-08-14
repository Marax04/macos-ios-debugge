// Exercises: struct field recovery, loop-flag conditions, array indexing.
// Compiled AOT (Native AOT) so it produces a real native PE rather than IL,
// making it comparable to the C/C++/Rust/Go samples.
using System;

struct Point
{
    public long X;
    public long Y;
    public long Sum;
}

static class Program
{
    static long Accumulate(Point[] pts)
    {
        long total = 0;
        for (int i = 0; i < pts.Length; i++)
        {
            pts[i].Sum = pts[i].X + pts[i].Y;
            total += pts[i].Sum;
        }
        return total;
    }

    static long FindMax(long[] arr)
    {
        long best = arr[0];
        for (int i = 1; i < arr.Length; i++)
        {
            if (arr[i] > best)
            {
                best = arr[i];
            }
        }
        return best;
    }

    static int Main()
    {
        var pts = new Point[]
        {
            new Point { X = 1, Y = 2, Sum = 0 },
            new Point { X = 3, Y = 4, Sum = 0 },
            new Point { X = 5, Y = 6, Sum = 0 },
        };
        long t = Accumulate(pts);
        long[] arr = { 10, 40, 20, 30 };
        long m = FindMax(arr);
        return (int)(t + m);
    }
}
