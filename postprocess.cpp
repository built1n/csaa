#include <iostream>
#include <stdio.h>
using namespace std;

/* post-process the output of tabulate.sh */
/* input:
   [x1] [y1_0]
   [x1] [y1_1]
   ...
   [x2] [y2_0]
   [x2] [y2_1]
   ...
   [x] is an integer up to 100
*/
/* output:
   [x1] [average y1]/2^[x1] [stddev y1]
*/

static double sums[100] = { 0 }, means[100] = { 0 }, deltasq[100] = { 0 };
static int counts[100] = { 0 };

int main()
{
    while(cin)
    {
        int x;
        double y;
        cin >> x >> y;

        long long div = 1 << x;

        sums[x] += y / div;
        counts[x]++;
    }
    for(int i = 0; i < 100; ++i)
    {
        if(counts[i])
        {
            means[i] = sums[i] / counts[i];
            printf("%d %g\n", i, means[i]);
        }
    }
}
