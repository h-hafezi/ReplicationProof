# Proof of Replication

Golang implementation of ["Proofs of Replicated Storage Without Timing Assumptions"
](https://eprint.iacr.org/2018/654.pdf).

Here we check out some important implementation details.
## Invertible Random Oracles
The notation of Invertible Random Oracles is used in the paper, in which we implement it with Encrypt-Mix-Encrypt encryption mode developed by Halevi and Rogaway in 2003 (["A Parallelizable Enciphering Mode"](https://eprint.iacr.org/2003/147.pdf)). We use the implementation of the [following link](https://github.com/horizonliu/eme/blob/0574c832dde8/eme.go). An alternative way is using Cipher Block Chaining (CBC) Mode, performance-wise they are similar and EME is highly parallelizable.

## Trapdoor Permutation
 The best candid is RSA but we need them to have an equal domain, there's a trick which we can use from the original ring signature paper (["How to Leak a Secret
"](https://people.csail.mit.edu/rivest/pubs/RST01.pdf)). We need to extend trapdoor permutations to the same domain. We extend all permutations to have a common domain of $\{0,\,1\}^b$ where $2^b$ is larger than all modulo $N_i$. Let $f_i$ be over $\mathbb{Z}_{N_i}$, we extend it to reach permutation $g_i$ over $\{0,\,1\}^b$ in the following way:
 * For any $b$-bit input $m$ define nonnegative integers $q_i$ and $r_i$ that $m=q_in_i+r_i$ where $0\le r_i\lt n_i$.
 
$$g_i(m)=\begin{cases}q_in_i+f_i(r_i)&:(q_i+1)n_i\le 2^b\\
m&:\mbox{else}\end{cases}$$

Intuitively, $g_i$ is defined by using $f_i$ to operate on the low-order digits of $n_i$ leaving the higher-order digits unchanged. The exception is when this might cause a result larger than $2^b-1$ in which $m$ is unchanged.

## Parameters
- Number of rounds: $r>(cn+1) k / B$
  - $k=\log |\mathcal{D}|$ where $\mathcal{D}$ is the domain of $f$ $\implies k=\log 2048=11$
  - $c$, the percentage of data compression that we are okay with $\implies c=0.95$
  - $n$, number of replications $\implies n=5$
  - $B$, the function is $B$-leakage inversion of the permutation $f\implies B=\log k =\log\log|\mathcal{D}|=\log11\approx 3$

 
We can conclude number of rounds we need for $n=5$ replicas with soundness certainty of $c=0.95$ is almost $20$ rounds.

   $$\implies \frac{(0.95 \times 5 + 1)\times 11}{3}\approx 20$$

## Efficiency
- CPU
  - Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz   2.71 GHz
- Encoding a single block (20 rounds of RSA)
  -  162.4184 (ms)
- Decoding a single block (20 rounds of RSA)
  -  1.637543 (ms)

