# ECDSA Digital Signature tests


## Motivation

The one-time secret k used to generate DSA and ECDSA signatures should be chosen
uniformly at random in the range 1 .. n where n is the order of the underlying
group (i.e. the parameter q of DSA rsp. the parameter n of ECDSA). If k is not
uniformly distributed then this is a weakness that may be exploited to find the
private key.

An example of such a weakness is the [U2f] vulnerability. Here a programming
error resulted in values $k$ of the form `aaaabbbbccccddddeeeeffffgggghhhh`,
where `a,b,c,d,e,f,g,h` are random bytes.

One goal of the signature tests is to detect such biased values $k$.
Generally, the discussion distinguishes between the case where the private key
is known and the case where the private key is not known. The discussion also
distinguishes between the case where the weakness is known and the case where
the weakness is not known.

Knowing the private key that was used to generate ECDSA signatures allows to
extract the values $k$ from the signatures. Hence in the case of the U2F ECDSA
vulnerability the weakness can be easily detected with simple statistical tests.
Generally, it is therefore preferable to test an implementation with the
knowledge of some private test keys. Paranoid often does not have access to
private keys. Additionally the number of signatures is typically limited. This
makes the detection of weaknesses more difficult and less reliable. In the case
of the U2F ECDSA vulnerability special case code was added that detects the
weakness given 2 signatures. The project also aims to detect similar weaknesses,
since programming errors are typically not predictable. The generalized method
described below are able to detect the same weakness too, but requires 23
signatures to be successful.

A similar situation is the case of linear congruential generators. If the
parameters of the generator are known then in many cases it is possible to
detect them with 2 signatures. If the parameters of the LCG are not known then
10-20 signatures are a typical requirement. If the LCG is truncated (i.e. only
the upper half of its state is used) then at least 20-40 signatures are needed
for a successful detection.

## Weaknesses in the signature generation

We analyze a number of different weaknesses in the generation of ECDSA
signatures.

**Incorrect range:** The random number k used in ECDSA may have less bits than
the size of the field elements in a signature. This weakness is quite common.
E.g., jdk had a flaw in the DSAWithSHA1 implementation which used 160 bit k's
independently of the size of the key. Phong Nguyen reported the same bug in GPG.
Breitner and Heninger [[BreHen]] found k's of size 64 bits, 110 bits, 128 bits,
and 160 bits. The [ethercombing] vulnerability reported a large number of weak
EC keys.

**Fixed bits:** The random number k may contain a bit sequence that is the same
in every signature. [[BreHen]] report such cases.

**LCGs:** Linear congruential generators are often used in random number
generators provided by standard libraries. The use of LCGs can often be found in
experimental implementations of ECDSA. Hence there is a chance that such
implementations may also be used in production.

The difficulty of detecting LCGs depends on the size of the register. Large
register often simplify the detection since there is less integer overflow to
consider. Truncating the output makes detection a bit more difficult.
Fortunately, the methods proposed in this note are general enough to deal with
truncation. java.util.random additionally reverts the byte order of the output.
This destroys most of the algebraic properties of LCGs. This makes it tricky to
detect this RNG hidden in ECDSA signatures.

For java.util.random and the random number generator in GMP, we have actual
implementations and hence it is possible to generate precomputed models for
these generators. For the other LCGs mentioned in this note we only know the
parameters, but not the byte order, hence such models are not yet possible.

**Hidden subset sum:** One potential mistake is to compute ECDSA signatures from
a set of precomputed pairs $(k_i, k_i G)$ [[BoPeVe]]. Such an approach can
easily lead to a non-uniformly distributed values k. If the number of
precomputed values is small enough and sufficiently many signatures are known
then it is possible to determine the precomputed values [[NguSte]], [[CorGin]].

**u2f:** The [U2f] vulnerability was caused by a programming error. The effect
of the error was that the k's used for the signatures repeated each byte 4
times. The goal here is to catch a large class of such errors without knowing
the nature of the error.

## Methods to detect weak pseudorandom numbers in ECDSA signatures.

A powerful and flexible approach to detect ECDSA signatures with weak k's is
to use lattice basis reduction [[HowSma]], [[Nguyen]], [[BreHen]], etc. Several
checks implemented in paranoid are based on this approach. The first step is to
define some variant of a hidden number problem. From a set of ECDSA signatures
$(r_i, s_i)$ for messages $m_i$ one computes pairs $(a_i, b_i)$ with the
property

$$k_i = a_i + b_i x \pmod{n},$$

where $x$ is the private key, $n$ is the order of the EC subgroup. I.e.,
$a_i = h(m_i) s_i^{-1} \bmod{n}$ (where $h(m_i)$ is the leftmost bits of the
hash digest of the message $m_i$) and $b_i = rs^{-1} \bmod{n}.$ Ideally the
values $k_i$ are uniformly distributed. If they have not a uniform
distribution then it might be possible to detect such a weakness and recover the
secret key $x$.

The checks in paranoid can be divided into a number of classes:

**General checks:** The goal is to detect serious weaknesses without having
advance knowledge of the weakness. One particular goal of such checks is to
detect programming errors such as the [U2f] vulnerability. The disadvantage of
such general checks is that they typically require a larger number of signatures
with the same flaw and that smaller biases are not detectable.

**Detecting a bias:** If the random number k's used in ECDSA signatures are
generated with a weak pseudorandom number generator then it is often possible to
find values $(c, d)$, such that $c k_i + d \pmod{n}.$ is biased. A simple
example of such a detection is the following: if a random number k for an ECDSA
signatures over the curve secp256r1 is generated by java.util.random then
multiplying k by

`c = 0x1000000fdffffff02000000ff010000ffbae6f76bd22b527d6141af32c030`

results in a value with 5-6 bits bias (i.e. the difference between $ck$ and
the closest multiple of the group order n is approximately 250 bits long). The
bias is big enough that signatures generated with java.util.random can be
detected with 60-70 signatures.

An improvement is possible by noting that there are many such pairs
$(c_i,d_i)$ leading to similarly big biases. Combining these pairs can often
reduce the number of necessary signatures to just 2.

**Detecting linear combinations of a set of generators:** Another method to
detect weak generators for the values $k$ is to express the values $k$ as
linear combinations of a small set of generators with small coefficients.

A simple example is the Cr50 weakness. Here the values $k$ have the format
`aaaabbbbccccddddeeeeffffgggghhhh`, where a,b,c,d,e,f,g,h are random bytes.
Hence the k's are linear combinations of the set
$\{1010101_{16} \cdot 2^{32 j}: 0 \leq j \leq 7\}$.

### Precomputation

For known weak PRNGs it is sometimes possible to build a model that allows to
detect them with a small number of signatures. For example precomputation
allowed to reduce the number of necessary signatures generated with
java.util.random from initially about 60 down to just 2 signatures.

We generally use the following approach:

(Step 1) Generating sets of random k's with the weak pseudorandom number
generator.

(Step 2) Run a detection algorithm for the scenario where the pseudorandom
number generator is not known but all the random numbers are known. One choice
is to use the compute short vectors of the lattice

$$ L_1 = \left[\begin{matrix}
w   & k_1 & k_2 & k_3 & \ldots \\
    & 1   & 1   & 1   & \ldots \\
    &     & n   &     & \ldots \\
    &     &     & n   & \ldots \\
    &     &     &     & \ldots
\end{matrix}\right]$$

This lattice finds values $c, d$, such that $c \cdot k_i + d$ are all close
to multiples of n. This step is repeated with different sets of k's with the
hope that it finds different sets (c, d), such that all of them expose a bias in
the output of the pseudorandom number generator.

(Step 3: bagging) Many pseudorandom number generators return several hundred
constant pairs $(c_i, d_i)$ as described above. In such cases we want to make
a good selection of constants. We try to select constants with a large bias and
additionally tries to avoid constants where the values $c_i$ are linear
combinations of each other with small coefficients. I.e., At this point we use
the following ad hoc method:

(3.1) Generate a large sample with outputs $k_i$ from the pseudorandom number
generator.

(3.2) For each pair $(c_j, d_j)$ compute the bias of $k_i c_j + d_j$ over
all $k_i$.

(3.3) Sort the pairs $(c_j, d_j)$ by the computed bias (i.e. pairs with a
large bias first).

(3.4) For each j try to find small coefficients $w_i$ such that

$$\sum_{i=0}^j c_i w_i \equiv 0 \pmod{n}.$$

If coefficients exist that are smaller than a given bound then reject the pair
$(c_j, d_j)$. Otherwise add it to the model.

### Building a lattice from precomputed constants

We are given a set of precomputed values $(c_j, d_j)$ that all have the
property that the values $k_i c_j + d_j$ are biased. Hence we can use

$$k_i \cdot c_j + d_j \equiv a_i \cdot c_j + d_j  + b_i c_j  x \pmod{n}$$

and thus use the lattice

$$ L_2 = \left[\begin{matrix}
m &     & e_{11} & e_{12} & e_{13} & \ldots \\
  & m/n & f_{11} & f_{12} & f_{13} & \ldots \\
  &     &  n     &        &        & \ldots \\
  &     &        & n      &        & \ldots \\
  &     &        &        & n      & \ldots \\
  &     &        &        &        & \ldots
\end{matrix}\right]$$

with $e_{ij} = a_i c_j + d_j$ and $f_{ij} = b_i c_j.$ The value $m$ is
roughly the expected bias.

This lattice contains a short vector that is a linear combination of x times the
first row and 1 times the second row. Hence we can hope that applying LLL can
find x.

### Normalized signatures

Implementations over the curve secp256k1 typically normalize the signature
$(r,s)$ by replacing it with $(r, min(s, n - s))$ to avoid signature
malleability. To build a model that detects weak pseudorandom number generators
for normalized signatures one can simply add additional values $n - k_i$ to
the precomputation.

## Checks

### CheckLCGNonceGMP

Checks whether the values $k$ were generated by GMP. The random number
generator in GMP uses a linear congruential generator with a number of register
sizes. The output of this LCG is truncated. Each step outputs the upper half of
the state of the LCG.

The test uses a precomputed model to detect signatures generated by GMP with a
small number of signatures. The following table contains the number of
signatures necessary for some selected curves.

Output size | secp256r1 | secp384r1 | sep521r1
----------- | --------- | --------- | --------
16          | 2         | 2         | 2
20          | 2         | 2         | 2
28          | 2         | 2         | 2
32          | 2         | 2         | 2
64          | 3         | 2         | 2
98          | 5         | 2         | 2
100         | 6         | 3         | 3
128         | -         | 4         | 4

### CheckLCGNonceJavaUtilRandom

Checks whether the values k were generated by java.util.random.

java.util.random uses a LCG with a 48 bit state. At each step it outputs the 32
most significant bits of the state. The byte order of the output is reversed.
This makes detection more difficult. At the moment we have a precomputed model
that is able to detect java.util.random given 2 signatures over secp256r1 in
about 60-70% of the cases. For larger curves we have not been able to precompute
a model that has significant success.

### CheckNonceMSB

Checks whether the values k have most significant bits as 0. Breitner and
Heninger [[BreHen]] have done an extensive analysis of ECDSA signatures against
this kind of flaw and found a large number signatures with such a weakness.

### CheckNonceCommonPrefix

Checks whether the values k have the same most significant bits. We tried to use
two different lattices

$$L_3 = \left[\begin{matrix}
 m   &     & a_1 & a_2 & a_3 & \ldots \\
     & m/n & b_1 & b_2 & b_3 & \ldots \\
     &     & 1   & 1   & 1   & \ldots \\
     &     &     & n   &     &        \\
     &     &     &     & n   &        \\
     &     &     &     &     & \ldots
\end{matrix}\right]$$

and a variant with a smaller dimension.

$$L_4 = \left[\begin{matrix}
m & & a_1 - a_2 & a_1 - a_3 & \ldots \\
  & m/n & b_1 - b_2 & b_1 - b_3 & \ldots \\
  & & n & & \\
  & & & n & \\
  & & & & \ldots \end{matrix}
\right]$$

Tests so far indicate that both lattices are about equally powerful.

### CheckNonceCommonPostfix

Checks whether the values k have the same least significant bits. Multiplicative
properties can be used here. If $m$ least significant bits of all the values
$k_i = a_i + b_i x \pmod{n}$ are common then roughly the $m$ most
significant bits of $k_i 2^{-m} = a_i 2^{-m} + b_i 2^{-m} x \pmod{n}.$ And
hence the same method used in CheckNonceCommonPrefix can be used here too.

### CheckNonceGeneralized

This check uses a generalized method for finding biased values k.

Checks whether there are integers (c, d) such that values $c k_i + d \bmod n$
are biased, where n is the curve order. This is achievable with a matrix

$$L_5 = \left[\begin{matrix}
 m/n &     & a_1 & a_2 & a_3 & \ldots \\
     & m/n & b_1 & b_2 & b_3 & \ldots \\
     &     & 1   & 1   & 1   & \ldots \\
     &     &     & n   &     &        \\
     &     &     &     & n   &        \\
     &     &     &     &     & \ldots
\end{matrix}\right]$$

If $u$ and $v$ are the coefficients of the first and second row of a linear
combination resulting in a short vector then $v u^{-1} \bmod n$ is potentially
the private key.

This lattice is quite powerful. It can find a large range of biases given
sufficiently many signatures:

*   It can find the private key given 23 signatures with the U2F ECDSA
    vulnerability. A specialized check for this vulnerability can detect the
    weakness given only 2 signatures. The advantage of the generalized method
    here is that no prior knowledge of the weakness is necessary. Thus it will
    hopefully detect similar programming errors.
*   It can find some generators where the bias is in the middle of the value k.
*   It can find the private key given maybe 12 - 24 signatures where k is
    generated with a linear congruential generator. The parameters of the LCG do
    not need to be known in advance for the method to work. For pseudorandom
    number generators that are widely used it is possible to train concrete
    models that detect specific cases with less signatures.
*   It can find find some truncated linear congruential generators without
    knowing the parameters.

Linear congruential generators are frequently detectable given sufficiently many
signatures. An experiment with LCGs from a list of
[common LCGs](https://en.wikipedia.org/wiki/Linear_congruential_generator) gives
the following results:

name               | state/truncation | secp256r1 | secp384r1 | secp521r1
------------------ | ---------------- | --------- | --------- | ---------
glibc              | 31/0             | 20        | 28        | 38
numerical recipies | 32/0             | 19        | 28        | 36
borland c/c++      | 32/16            | 43        |           |
posix              | 48/0             | 15        | 20        | 26
posix truncated    | 48/16            | 23        | 32        | 41
MMIX               | 64/0             | 12        | 16        | 20
newlib             | 64/16            | 26        |           |
Ecuyer             | 128/64           | 22        |           |
MWC 16             | 32/16            | 39        | -         |
MWC 32             | 64/32            | 23        | 30        | 42
MWC 64             | 128/64           | 15        | 16        | 21
MWC 128            | 256/128          | -         | 15        | 15
gmpy32_16          | 32/16            | 43        | 62        | 84
gmpy40_20          | 40/20            | 36        | 50        | 66
gmpy56_28          | 56/28            | 28        |           | 37
gmpy64_32          | 64/32            | 26        |           | 33
gmpy128_64         | 128/64           | 22        |           | 23
gmpy196_98         | 196/98           | 35        |           | 23
gmpy200_100        | 200/100          | 37        |           | 23
gmpy256_128        | 256/128          | -         |           | 27

### CheckCr50U2f

Checks whether the signatures use weak values k like in the [U2f] flaw. Here the
values $k$ are of the form `aaaabbbbccccddddeeeeffffgggghhhh`. Hence all the
values $k$ can be represented as linear combinations of integers
$1010101_{16} \cdot 2 ^ {32 j}$ with coefficients in the range 0..255.
Detecting such linear combinations can be done with 2 signatures.

In principle it is possible to detect a single weak instance using the baby-step
giant-step algorithm in $2^{32}$ steps. Currently we have not implemented this
approach.

### CheckIssuerKey

Checks whether the signature issuer public keys are weak.

Runs all EC key tests against the issuer public keys. For this check we set the
default severity as UNKNOWN but when a signature has a weak issuer key, we
assign the same severity of the key check that found the issuer key as weak.

<!-- Literature -->

[BoPeVe]: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.52.2547&rep=rep1&type=pdf "V. Boyko, M. Peinado, R. Venkatesan, Speeding up Discrete Log and Factoring Based Schemes via Precomputations"
[BreHen]: https://eprint.iacr.org/2019/023.pdf "Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies"
[BGM]: https://cseweb.ucsd.edu/~mihir/papers/dss-lcg.pdf "M. Bellare, S. Goldwasser, D. Micciancio, Pseudo-Random Number Generation within Cryptographic Algorithms: the DSS Case"
[CorGin]: https://eprint.iacr.org/2020/461.pdf "J.-S. Coron, A. Gini, A Polynomial-Time Algorithm for Solving the Hidden Subset Sum Problem"
[HowSma]: https://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf "N.A. Howgrave-Graham, N.P. Smart, Lattice Attacks on Digital Signature Schemes"
[Nguyen]: https://cr.yp.to/bib/2001/nguyen.ps "The Two faces of lattices in Cryptology"
[NguSte]: https://link.springer.com/content/pdf/10.1007%2F3-540-48405-1_3.pdf "P. Nguyen, J. Stern, The Hardness of the Hidden Subset Sum Problem and Its Cryptographic Implications"
[ethercombing]: https://www.ise.io/casestudies/ethercombing/
[U2f]: https://www.chromium.org/chromium-os/u2f-ecdsa-vulnerability/ "U2F ECDSA vulnerability"
