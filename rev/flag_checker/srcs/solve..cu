#include <iostream>
#include <cuda.h>
#include <curand_kernel.h>
#include <map>



// https://docs.nvidia.com/cuda/cuda-runtime-api/group__CUDART__TYPES.html
#define CHECK(val) check_cuda( (val), #val, __FILE__, __LINE__ )
void check_cuda(cudaError_t res, const char *func, const char *file, const int line)
{
	if (!res)
		return ;
	std::cerr << "CUDA error = " << static_cast<unsigned int>(res);
	std::cerr << " at " << file << ":" << line << " '" << func << "' \n";
	cudaDeviceReset();
	exit(1);
}

typedef unsigned long long ull;

__device__ ull test_pt[] = {0x2265B1F5LL, 0x91B7584ALL, 0x0D8F16ADFLL, 0x0CD613E30LL, 0x0C386BBC4LL, 0x1027C4D1LL, 0x414C343CLL, 0x1E2FEB89LL};
__device__ ull test_ct[] = {0x0DC44BF5ELL, 0x5AFF1CECLL, 0x0E1E9B4C2LL, 0x1329B92LL, 0x8F9CA92ALL, 0x0E45C5B4LL, 0x604A4B91LL, 0x7081EB59LL};


__device__ ull F(ull a1, ull a2, ull a3)
{
  ull v5;
  ull v6;

  v5 = 1LL;
  v6 = a1 % a3;
  while ( a2 > 0 )
  {
    if ( (a2 & 1) != 0 )
      v5 = v6 * v5 % a3;
    v6 = v6 * v6 % a3;
    a2 >>= 1;
  }
  return v5;
}

__global__ void	brute() {
	ull exp = threadIdx.x + (blockIdx.x + (blockIdx.y + blockIdx.z * 256) * 256) * 256;
	for ( int i = 0; i <= 7; ++i ){
		if (F(test_pt[i], exp, 0xFFFFFF2FLL) == test_ct[i] ) {
			printf("Found: %d %016llx\n", i, exp);
		}
	}
}

int main(void)
{
	clock_t			start;
	clock_t			stop;

	dim3	blocks(256, 256, 256);
	dim3	threads(256);

	start = clock();

	brute<<<blocks, threads>>>();
	CHECK(cudaGetLastError());
	CHECK(cudaDeviceSynchronize());

	stop = clock();
	std::cerr << "Took: " << ((double)(stop - start)) / CLOCKS_PER_SEC << "\n";

	return (0);
}
