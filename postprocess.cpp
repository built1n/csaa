#include <iostream>
#include <stdio.h>
#include <cmath>
#include <cstring>

using namespace std;

/* Huge hack. */

/* post-process the output of tabulate.sh */
/* input:
   [x1] [y1_0] [div1_0]
   [x1] [y1_1] [div1_1]
   ...
   [x2] [y2_0] [div2_0]
   [x2] [y2_1] [div2_1]
   ...
   [x] is an integer up to 100
*/
/* output:
   [x1] [average y1]/[div_n] [stderr y1]
*/

static double values[100][100], sums[100], means[100], stddevs[100], stderrs[100];
static int counts[100] = { 0 };

int main()
{
    memset(counts, 0, sizeof(counts));
    while(cin)
    {
        int x;
        double y;
        unsigned long long div;
        cin >> x >> y >> div;

        values[x][counts[x]] = y / div;
        sums[x] += values[x][counts[x]];

        counts[x]++;
    }
    for(int i = 0; i < 100; ++i)
    {
        if(counts[i])
        {
            means[i] = sums[i] / counts[i];

            double var = 0;
            for(int j = 0; j < counts[i]; ++j)
            {
                double del = (values[i][j] - means[i]);
                var += del * del;
            }

            if(counts[i] == 0)
                stddevs[i] = 0;
            else
                stddevs[i] = sqrt(var / (counts[i] - 1));

            stderrs[i] = stddevs[i] / sqrt(counts[i]);

	    /* 95% confidence interval */
	    double z = 1.96;
            printf("%d %g %g\n", i, means[i], z * stderrs[i]);
        }
    }
}
