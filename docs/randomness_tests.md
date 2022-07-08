# Randomness tests


NOTE: The tests are work in progress and are currently not stable.

## Goal of the tests

Most of the tests in Paranoid check public keys for flaws. It is much more
difficult to detect a weak pseudorandom number generator when its output is a
secret used to generate a public key or signature.

The tests in this component are meant for situations where the pseudorandom
numbers are accessible but not the implementation. A typical situation is when
the tester has access to the generator and is able to generate a list of new
private keys for testing. Similarly, when testing ECDSA signatures it is helpful
if these signatures were generated with a test key and the private key is
accessible during the analysis, since in this case the pseudorandom numbers used
to generate the signature can be recovered.

The main goal of the tests is to detect implementation flaws. The pseudorandom
number generator is not the only place that can contain flaws. Incorrectly using
even a strong pseudorandom number generator can by itself introduce exploitable
errors. Hence one of the goals is to add tests that allow the analysis of key
generation and signature generation.

## Non-goals

We'd like to emphasize that statistical tests cannot replace an analysis of the
implementation of a pseudorandom number generator. Statistical tests simply find
flaws, they cannot measure the quality of a pseudorandom number generator.

Sometimes authors of pseudorandom number generators use statistical tests to
compare the quality of their proposal by counting the number of test failures in
statistical tests. Such comparisons are suspicious. It is typically easy to
camouflage weaknesses against a suite of statistical tests with some bit
fiddling. Additionally we parameterize the tests, so that they do recognize weak
random number generators. Hence failing no tests doesn't indicate that a random
number generator has any strength, it doesn't even indicate that a pseudorandom
number generator is stronger than other weak "competitors".

## Usage

A typical use of the test is as follows:

Step 1: Defining the source to test

```python
def MyPrng(number_of_bits: int) -> int:
  # calls the pseudorandom number generator to test.
  # E.g., return random.getrandbits(number_of_bits)
```

Step 2: Calling the test suite.

```python
randomness_tests.TestSource(
    source_name="MyPrng",
    source = MyPrng,
    n = 10000000,
    significance_level_repeat = 0.01,
    significance_level_fail = 1e-9)
```

There are plans to add additional interfaces to better support different use
cases. At the moment we consider the following use cases:

*   **Testing a new implementation for flaws**: This use case should probably
    use a large input size (e.g. at least 100 MB.)

*   **Unit tests**: Probably uses input sizes of maybe 128 kB depending on the
    amount of time one wants to spend during a unit test.
    significance_level_fail should be low enough not to generate false positives
    (e.g. 1e-9).

*   **Health checks**: Those are checks that run at runtime and with the goal to
    detect broken hardware. For situations where these checks can't run for a
    long time it may be possible to add a new interface that only runs quick
    statistical tests and skipps more CPU excessive tests that detect weak PRNGs
    and design flaws.

*   **Project specific checks**: Typically it is a good idea to test
    pseudorandom output as close to the source as possible. If the interfaces
    provided are not a good match for a given project we'll try to provide a
    better one.

## Tests

### NIST SP 800-22

NIST SP 800-22 describes a test suite with statistical tests. We have
implemented this test suite. However, there are differences. Tests that are
implemented differently are described below. A major difference is the strategy
used to evaluate p-values of multiple runs. This is described in Section
"Repeating tests".

#### Frequency (Monobits) Test

This test is described in Section 2.1 of NIST SP 800-22. The test checks whether
the distribution of 0 and 1 bits is sufficiently random.

#### Frequency Test within a Block

This test is described in Section 2.2 of NIST SP 800-22. The test divides the
input into blocks, counts the number of 0 and 1 bits in each block and then
compares the distribution against the distribution of random input.

**Plans:** The test should be extended to check multiple block sizes.

#### Runs Test

This test is described in Section 2.3 of NIST SP 800-22. The test counts the
number of runs in a bit string and compares the result against the expectation
for a random input.

#### Test for the Longest Run of Ones in a Block

This test is described in Section 2.4 of NIST SP 800-22. The test divides the
input into blocks, computes the length of the longest run of ones in each block
and compares the result against the expectation for random inputs.

#### Binary Matrix Rank Test

This test is described in Section 2.5 of NIST SP 800-22. The test constructs
quadratic binary matrices from the input, computes the rank of each matrix and
compare the distribution of the ranks against the distribution of the rank of
random matrix.

**Differences:** NIST uses asymptotic values for the distribution of the
results, since the test uses sufficiently large matrices of size 32*32. Since
other test suites use smaller matrices (e.g. diehard uses 6*8 in one test) the
probability distribution is recomputed in our implementation. This can lead to
small differences in the p-values.

#### Discrete Fourier Transform (Spectral) Test

This test is described in Section 2.6 of NIST SP 800-22. The test computes a
discrete Fourier transform over the input bits and then compares the number of
large results against the expectation for random inputs.

**Plans:** [Wikipedia](https://en.wikipedia.org/wiki/Spectral_test) claims that
the spectral test can be used to analyze LCGs. So far only lcgnist can be
detected with this test. Other LCGs implemented for testing pass this test. This
raises the question if there are variants that can be used here.

#### Non-Overlapping Template Matching Test

This test is described in Section 2.7 of NIST SP 800-22. The test counts the
number of occurrences of non-overlapping templates and compares the number
against the number expected for random input. Each template tested returns a
p-value. Since many templates are possible typical significance level (e.g.
0.01) will likely result in some false positive each time the test is run. Our
implementation allows to automatically repeat tests with small p-values, so that
false positives can be suppressed.

#### Overlapping Template Matching Test.

This test is described in Section 2.8 of NIST SP 800-22. The test counts the
number of occurrences of overlapping templates. The test is comparable to the
"non-overlapping template test". Because templates can overlap the distribution
of the result is different.

**Differences:** Our implementation uses a slower, but hopefully more accurate
method to compute the p-value. Hence the result can differ from NIST's
implementation.

#### Maurer’s “Universal Statistical” Test

This test is described in Section 2.9 of NIST SP 800-22. The test is an
implementation of the paper "A universal statistical test for random bit
generators" by Ueli M. Maurer, Journal of Cryptology volume 5, pp. 89–105
(1992).

#### Linear Complexity Test

This test is described in Section 2.10 of NIST SP 800-22. The test computes the
linear complexity of subsequences of the input and compares the distribtuion
against the distribution of random sequences.

The algorithm used in our implementation is described in the paper "Algorithm
970: Optimizing the NIST Statistical Test Suite and the Berlekamp-Massey
Algorithm", ACM Transactions on Mathematical Software, vol. 43, num. 3, Sep.
2017.

**Differences:** The test as proposed by NIST focuses on the distribution of the
linear complexities. It treats any linear complexity outside a certain distance
from the median value in the same way. However, finding just a single
sub-sequence with a linear complexity that is sufficiently different than the
median value may indicate that the input is not random. Our implementation
computes an additional p-value that focuses on the occurrence of unlikely linear
complexities.

#### Serial Test.

This test is described in Section 2.11 of NIST SP 800-22. The test counts the
number of occurrences of overlapping m-bit patterns and checks if the number of
occurrences deviates from random input.

**Differences:** The test proposed by NIST takes the size m of the patterns as
an input parameter. Since it is possible to compute the count of m-1 bit
patterns from the count of m-bit patterns it is almost as efficient to run the
test for a range of values of m at the same time. Each value of m returns 2
p-values.

#### Approximate Entropy Test

This test is described in Section 2.12 of NIST SP 800-22. The test compares the
frequency of m and m+1 bit pattern and compares the result against the
expectation from random input.

**Differences:** The test proposed by NIST takes the size m of the patterns as
an input parameter. As in the serial test it is possible to compute the
frequencies of m-bit patterns from the frequency of m+1 bit pattern. Hence the
implementation runs the test for a range of (hopefully) reasonable values of m.
Each value of m returns a p-value.

**Plans:** Section 2.12.7 recommends an upper bound for m. In some cases this
bound appears to be too optimistic and the test can fail even if the input has
been generated by a strong pseudorandom number generator. At the moment it is
not clear what upper bound should be chosen.

Additionally, some PRNGs could be detected because their output may be too
uniform. For example lcgnist consistently returns p-values close to 1.0. Hence
we might consider to add an additional p-value to detect such cases.

#### Cumulative Sums (Cusum) Test.

This test is described in Section 2.13 of NIST SP 800-22.

The input bits are used to perform a 1-dimensional random walk. The test checks
if the maximal distance from the origin deviates too much from the expected
value.

The test is implemented in the method RandomWalk. This implementation merges the
cumulative sums test with the random excursion tests, since all of them perform
the same random walk, but compute different statistics out of the result.

#### Random Excursions Test.

This test is described in Section 2.14 of NIST SP 800-22. The test is
implemented in the method RandomWalk, which merges several tests.

The random excurions test requires that the random walk produces a minimal
number of cycles. In about 30% of all cases there are not enough cycles to give
conclusive results, and hence no p-values are computed.

#### Random Excursions Variant Test

This test is described in Section 2.15 of NIST SP 800-22. The test is
implemented in the method RandomWalk, which merges several tests.

Similar to the random excurions test this test requires that the random walk
produces a minimal number of cycles. In about 30% of all cases there are not
enough cycles, and hence no p-values are computed.

### Additional tests

#### FindBias

The test uses an LLL based approach to find biases in pseudorandom numbers. This
test can for example detect LCGs and truncated LCGs.

Pseudorandom number generators that fail this test can lead to especially
critical vulnerabilities when used in cryptographic schemes such as ECDSA. It is
quite feasible that the vulnerability can be detected without even knowing the
parameters of the pseudorandom number generator.

The test works by dividing the input into two set of samples. The first set of
samples is used to search for a distinguisher. The second set of samples is then
used to determine if the distinguisher can distinguish these samples from
random. A similar method has been used to determine the constants that are used
to detect ECDSA signatures generated with LCGs.

#### LargeBinaryMatrixRank

The binary matrix rank test proposed by NIST uses small matrices (e.g. 32x32).
This test computes the rank of large binary matrices. Since the p-value is
computed from the rank of single matrices the test only fails if the rank is
sufficiently smaller than the size of the matrix.

A number of weak random number generators can be detected by computing the rank
of larger binary matrices.

A few examples are below:

PRNG         | matrix size that detects weakness
------------ | ---------------------------------
xorshift128+ | 256 * 256
xorwow       | 512 * 512
xorshift*    | 2048 * 2048
gmp16        | 8192 * 8192
java         | 16384 * 16384
mt19937      | 32768 * 32768

**p-values:** Since the p-value is computed from the rank of a single matrix it
is not uniformly distributed. Rather the p-values take discrete values.

**Plans:** If a pseudorandom number generator can be distinguished from random
then it is typically possible to extract a distinguisher (i.e. coefficients for
a linear combination) that allows to detect the generator with less input. Our
plan is to add the capability to extract such distinguishers and add
distinguishers for common pseudorandom number generators to the test suite.

#### LinearComplexityScatter

The test interprets the input as n (e.g. n=32 or 64) interleaved bit strings.
The test computes the linear complexity of the resulting bit strings.

The motivation for this test is that weak pseudorandom number generators have
weaknesses where for example the least significant bits or the most significant
bit can be described with a LFSR. The test PRNGs that fail this test are:
mt19937, xorshift128+, xorwow and xorshift*.

The implementation of the Berlekamp-Massey algorithm has quadratic complexity.
The input sequence is truncated to avoid that this test takes significantly more
time than the remaining tests.

**Plans:** The Berlekamp-Massey algorithm can be sped up significantly with a
C++ implementation.

## Interface

TODO: Currently no stable interface exists.

The file paranoid_crypto/lib/randomness_tests/random_test_suite.py contains the
main interfaces. We plan to add several interfaces for different types of
inputs. I.e.,

*   a long bit string that is the output of a pseudorandom number generator.
    This is essentially the interface that NIST is using.
*   a source for generting pseudorandom bits. Allowing the test itself to
    generate more pseudorandom bits has some advantages. The most important one
    is that tests can be repeated when it is unclear if a small p-value
    indicates a test failure or just a random fluke.
*   a list of integers. It should be possible to test generated keys or random
    nonces used for signatures, since it is always possible that an
    implementation flaw is in the key generation rather than the pseudorandom
    number generator.

A goal of the implementation is to make the tests usable during unit testing. To
achieve this goal some provisions have to be made:

### Repeating tests

NIST uses a significance level of 0.01. This makes is very likely that at least
some of the tests fail at random, since there are hundreds of p-values computed
during each run. Therefore, a simple version of the test is not useful as a unit
test. It would be very flaky.

A strategy to avoid flaky behaviour is to repeat failing tests, e.g., all tests
with a p-value smaller than say 0.01. Multiple test results are combined with
[Fisher's method](https://en.wikipedia.org/wiki/Fisher%27s_method) to yield a
combined p-value. If the combined p-value is smaller than a much smaller bound
(e.g. 1e-9) then the test has failed.

Alternative methods exist. N. A. Heard compares such methods in
[Choosing Between Methods of Combining p-values](https://arxiv.org/pdf/1707.06897.pdf).
The main reason to use Fisher's method is that it is more sensitive to small
p-values than p-values close to 1.0. Tests have typically only a finite number
of possible outcomes. Hence the p-values cannot be uniformly distributed. We aim
to have the property that a p-value <= x happens at most with probability x.
This means that p-values can be "too large". For example LargeBinaryMatrixRank
computes the p-value from the rank of a single large matrix. Since a large
binary matrix has full rank the test returns a p-value of 1.0 with about 29%
probability.

**Differences:** NIST SP 800-22 describes in Section 4 a strategy to interpret
results from multiple test runs. Section 4.2.2 describes a method to evaluate
the distribution of p-values. To get meaningful results NIST recommends at least
55 test runs. This is too costly if the tests are run as unit tests.

Section 4.2.2 assumes that the p-values are uniformly distributed. However, not
every test (especially new tests that we added) has this property. E.g.,
LargeBinaryMatrixRank returns discrete results. Hence, adding NISTs strategy at
this moment would result in false positives.

There are weak pseudorandom number generator that can be caught with NISTs 2nd
level testing. For example lcgnist consistently returns p-values close to 1.0 in
the Serial test. Because of this it is possible to distinguish lcgnist from a
good pseudorandom number generator by analyzing the distribution of the
p-values.

We consider it somewhat unfortunate if a statistical weakness is only detected
with 2nd level testing. Hence, our aim is to add additional tests for such cases
and we consider 2nd level testing more of a tool to detect shortcomings in the
test suite itself.

## Testing

This section describes the component of randomness_tests that has been added to
test the test suite itself. This has been done because there are a number of
things that can (and do) go wrong:

*   Tests can be implemented incorrectly and as a consequence detect
    irregularities that do not exists.

*   The p-values can be too small. If a test is repeated several times then
    p-values that are computed as too small each time, then the combined p-value
    can incorrectly indicate a test failure.

*   Tests can be ineffective if they use the wrong parameters.

*   Weak pseudorandom number generators passing every test in the test suite may
    indicate that the test suite is incomplete.

### Pseudorandom number generators for testing

*paranoid_crypto/lib/randomness_tests/rng.py* contains a collection of
pseudorandom number generators for testing. Many of these random number
generators are weak and can be distinguished from a true random bit generator.
Indeed, their weakness was often the main motivation to include them into
rng.py.

A large fraction of these pseudorandom number generators are LCGs or are based
on LCGs. This is not an accident. The usage of LCGs in cryptographic primitives
(e.g., ECDSA) often leads to implementations that are easy to attack.

Currently the following pseudorandom number generators are defined:

#### urandom

os.urandom is expected provide random output suitable for cryptographic use.
Hence, this pseudorandom number generator should not fail a test consistently.

#### mt19937

Mersenne twister with 19937 bits of state. Currently the python module random
uses this pseudorandom number generator. Its output can be destinguished from
true randomness by computing the linear complexity of its output or by computing
the rank of a large binary matrix filled with its output. The parameters
proposed by NIST are too small to detect this pseudorandom number generator.

#### gmp_n

These are pseudorandom number generators defined in GMP. The pseudorandom number
generators use a truncated LCG. They use a state of 2*n bits. After each step
the n most significant bits of the state are returned.

All instances can be detected using lattice basis reduction. Instances with a
small register size often also fail other tests.

#### mwc_n

These are multiply-with-carry generators. These pseudorandom number generators
are special cases of LCGs. Hence they should be detectable with the same methods
as LFSRs. A reason to include them here, is that the parameters were chosen such
that even registers with larger sizes can be implemented easily. Thus
implementations of MWC tend to use larger states than typical LCGs.

#### java

This is the pseudorandom number generator implemented in java.util.Random. This
generator only uses a truncated LCG with a 48-bit state. It is rather easy to
detect.

#### lcgnist

This is a pseudorandom number generator included in NIST SP 800-22 for testing.
The pseudorandom number generator only outputs the most significant bit after
each step, but it uses a very small state of 32-bits. One test that detects this
generator is the Spectral test.

#### xorshift128+

xorshift128+ is an instance of a large family of pseudorandom number generators,
that are based on a LFSR. Its output is derived from the LFSR state using a
"slightly" non-linear function. This output function is too weak to hide the
internal structure of the generator. For example the least significant bit of
the output is a linear function of its state. Even if the generator is modified,
so that only the most significant bits are used, it is still possible to
distingish the output from random data.

#### xorshift*

xorshift* is another instance of the xorshift family of pseudorandom number
generators. It is based on an LFSR. It generates its output by multplying part
of the state with a 64-bit integer as a last step. This is of course poor
design. The multiplication is easily reversible. As such, the multiplication
only camouflages its weaknesses, but does not make the pseudorandom number
generator more difficult to predict.

#### xorwow

This pseudorandom number generator simply adds a counter to an LFSR. As a result
the output can be distinguished easily from random data.

#### pcg64, philox, sfc64

The main reason to include these pseudorandom number generators is that they are
implemented by numpy. Since we are using numpy for other things, we might as
well include the PRNGs too.

#### jsf32, jsf64

These pseudorandom number generators are proposed in
http://pracrand.sourceforge.net/RNG_engines.txt . They look somewhat
interesting, but we haven't analyzed them yet.

## Design decisions

The project is mainly written in Python. For this language there are a number of
powerful libraries available that can be used. One such example is fpylll, which
allows us to find a large number of potential weaknesses. E.g. an alternative
would have been to add this library to project Wycheproof, which is written in
java. The lack of good mathematical libraries would significantly hinder such an
implementation.
