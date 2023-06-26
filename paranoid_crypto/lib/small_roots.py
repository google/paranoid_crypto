# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Set of functions to find small roots of polynomials modulo an integer."""

import itertools
from typing import Optional
import gmpy
from paranoid_crypto.lib import linalg_util
from paranoid_crypto.lib import lll
import sympy


def _get_monomials(f: sympy.Poly) -> list[sympy.Poly]:
  mons = []
  for exps in f.monoms():
    mon = 1
    for i in range(len(exps)):
      mon *= f.gens[i]**exps[i]
    mons.append(sympy.Poly(mon, *f.gens))
  return mons


def univariate_modp(f: sympy.Poly, b: int, k: int = 3) -> Optional[int]:
  """Returns a small root of a univariate polynomial modulo an unknown factor.

  For a composite n, given a polynomial f(x) = 0 mod p, where p is an unknown
  factor of n, this function applies Coppersmith/Howgrave-Graham method to find
  a small root of f. The expected root should be smaller than the bound b. This
  function assumes that n is a balanced RSA modulus, i.e., n = p*q, where p and
  q have equal bit-lengths (beta = 1/2 by original Coppersmith method).

  E.g., for a polynomial f(x) = p0 + x and by using k = 2 the generated lattice
  has the triangular form:
  | n^2       0        0       0  |
  | n*p0     n*b       0       0  |
  | p0^2    2*p0*b    b^2      0  |
  |  0      p0^2*b  2*p0*b^2  b^3 |

  I.e., every new polynomial is a multiple of p and introduces exactly one new
  monomial to the lattice. The size of this lattice might be good enough for
  some situations but in order to achieve better results for a larger bound b,
  one can use a larger value of k. The maximum bound possible should be about
  half of the size of p, according to Howgrave-Graham theorem.

  Args:
    f: Univariate polynomial modulus n. This polynomial has to be 0 when mod p,
      where p is a factor of n.
    b: The maximum value of the expected root.
    k: A value that determines the size of the lattice. The dimension of the
      lattice is 2*k*d, where d is the degree of f.

  Returns:
    a small -b < root < b for the polynomial f if found, None otherwise.
  """
  if not f.is_univariate:
    raise ValueError('Polynomial is not univariate.')

  d = f.degree()
  dim = 2 * k * d
  n = f.get_modulus()
  fz = f.monic().set_domain(sympy.ZZ)
  x = fz.gen

  # compute polynomials
  pols = []
  xb = sympy.Poly(x * b)
  t = fz.compose(xb)
  for i in range(k):
    g = t**i * n**(k - i)
    for j in range(d):
      pols.append(xb**j * g)
  g = t**k
  for i in range(d * k):
    pols.append(xb**i * g)

  # create the lattice using the coefficients
  lat = [[0] * dim for _ in range(dim)]
  for i in range(dim):
    coeffs = pols[i].all_coeffs()[::-1]
    for j in range(i + 1):
      lat[i][j] = coeffs[j]

  lat = lll.reduce(lat)

  # reconstruct polynomial
  poly = sympy.Poly(sum(x**i * (lat[0][i] // b**i) for i in range(dim)))

  # Look for a linear/irreducible factor of the form a*x + b. Thus, the root
  # will be -b/a. This approach is much faster than calling one of the root
  # methods provided by sympy.
  for factor in poly.factor_list_include():
    rx = -factor[0].TC() // factor[0].LC()
    y = f(rx)
    if y != 0 and n % y == 0:
      return rx
  return None


def multivariate_modp(f: sympy.Poly,
                      bounds: list[int],
                      m: int = 4) -> Optional[list[int]]:
  """Returns small roots of a multivariate polynomial modulo an unknown factor.

  Proposal of M. Herrmann and A. May., 'Solving Linear Equations Modulo
  Divisors: On Factoring Given Any Bits', ASIACRYPT 2008. For a composite n,
  given a polynomial f = 0 mod p, where p is an unknown factor of n, this
  function applies Herrmann & May  method to find small roots of f. f has to be
  a linear equation f(x1, x2, ..., xl) = a0 + a1*x1 + a2*x2 + ... + al*xl.
  The expected roots should be smaller than the bounds. This function assumes
  that n is a balanced RSA modulus, i.e., n = p*q, where p and q have equal
  bit-lengths (beta = 1/2).

  The generated polynomials for the lattice are of the form
  g_i2,...,il,k = x2^i2 * x3^i3 * ... * xn^in * f^k * N^max{t-k, 0}, for an
  optimized t value, 0 <= k <= m, ij in {0...m} and sum(ij) <= m-k.
  I.e., every new polynomial is a multiple of p and introduces exactly one new
  monomial to the lattice. In order to achieve better results for larger bounds,
  one can use a larger value of m. The maximum product of bounds possible
  should be about n^0.25, according to Howgrave-Graham theorem. However, as
  discussed by Herrmann and May, with more unknowns it is natural to achieve
  smaller bounds. E.g., with two balanced unknowns, the product of the bounds
  is about n^0.207.

  E.g., for a polynomial f(x1, x2) = a0 + a1*x1 + a2*x2, the generated lattice
  has the triangular form:
  | n^t   0                                                        ... 0 |
  |    x2*n^t    0                                                 ... 0 |
  |       ...                                                      ... 0 |
  |          x2^m*n^t     0                                        ... 0 |
  |                  x1*n^(t-1)          0                         ... 0 |
  |                         ...                                    ... 0 |
  |                            x1*x2^(m-1)*n^(t-1)       0         ... 0 |
  |                                               x1^2*n^(t-2)   0 ... 0 |
  |                                                        ...     ... 0 |
  |                                                                 x1^m |

  Args:
    f: Multivariate polynomial modulus n. This polynomial has to be linear and 0
      when mod p, where p is a factor of n.
    bounds: A list with the maximum values of the expected roots.
    m: A value that determines the size of the lattice.

  Returns:
    list r of roots, with -bounds[i] < r[i] < bounds[i], for the polynomial f
      if found, None otherwise.
  """

  if not f.is_multivariate:
    raise ValueError('Polynomial is not multivariate.')
  if not f.is_linear:
    raise ValueError('Polynomial is not linear.')

  n = f.get_modulus()
  fz = f.monic().set_domain(sympy.ZZ)
  xs = fz.gens
  l = len(xs)
  # Herrmann and May suggest optimzed value t = tau*m, where
  # tau = 1-(1-beta)**(1/l). Assuming balanced RSA modulus, beta = 0.5:
  t = max(1, int((1 - (0.5)**(1 / l)) * m))

  # Compute polynomials. Each polynomial adds a new monomial.
  pols = []
  mons = []
  all_idxs = list(itertools.product(range(m + 1), repeat=l - 1))
  for k in range(m + 1):
    idxs = [idx for idx in all_idxs if sum(idx) <= m - k]
    g = fz**k * n**max(t - k, 0)
    mon = xs[0]**k
    for ijs in idxs:
      t1 = 1
      for i in range(1, l):
        t1 *= xs[i]**ijs[i - 1]
      pols.append(t1 * g)
      mons.append(t1 * mon)
  dim = len(pols)

  # create the lattice using the coefficients
  lat = [[0] * dim for _ in range(dim)]
  params = [sympy.Poly(xs[i] * bounds[i]) for i in range(l)]
  for i in range(dim):
    lat[i][0] = pols[i].TC()
    pol = pols[i]
    for v in range(l):
      pol = sympy.compose(pol, params[v], xs[v])
    pol = sympy.Poly(pol, *xs)
    for j in range(1, i + 1):
      lat[i][j] = pol.coeff_monomial(mons[j])

  lat = lll.reduce(lat)

  # reconstruct polynomials
  for i in range(dim):
    for j in range(dim):
      lat[i][j] = gmpy.mpz(lat[i][j]) // int(sympy.Poly(mons[j], *xs)(*bounds))

  # NOTE(pedroysb): Under the assumption that the lattice-based construction
  # yields algebraically independent polynomials, some papers suggest computing
  # resultants, Grobner basis, or multidimensional Newton method to find roots.
  #
  # As the assumption seems to hold for all rows of the lattice, a simpler (and
  # maybe faster) approach seems to be to consider every monomial as an
  # independent variable. The result is a linear system of dim-1 variables and
  # dim-1 equations.
  a = [lat[i][1:] for i in range(dim)]
  b = [-lat[i][0] for i in range(dim)]
  solutions = linalg_util.solve_right(a, b)
  if not solutions:
    return None
  mons_dict = dict(zip(mons[1:], range(len(solutions))))
  roots = [int(solutions[mons_dict[xi]]) for xi in xs]
  y = int(f(*roots))
  if y != 0 and n % y == 0:
    return roots
  return None


def multivariate_modn(f: sympy.Poly,
                      bounds: list[int],
                      m: int = 1) -> Optional[list[int]]:
  """Returns small roots of a multivariate polynomial modulo an integer.

  Proposal of E. Jochemsz and A. May., 'A Strategy for Finding Roots of
  Multivariate Polynomials with New Applications in Attacking RSA Variants',
  ASIACRYPT 2006. Given a polynomial f = 0 mod n, this function applies Jochemsz
  & May method to find small roots of f. f can be any polynomial with arbitrary
  degree. The expected roots should be smaller than the bounds.

  Compared to univariate_modp and multivariate_modp, this function is more
  appropriate to be used on vulnerabilities where the product of factors of n
  generate properties (e.g., unknowns) that do not exist or do not have enough
  information on the individual factors.

  First it defines the set of monomials:
  m_k = {x1^i1 * x2^i2 * ... * xn^in |
         x1^i1 * x2^i2 * ... * xn^in is a monomial of f^m and
        (x1^i1 * x2^i2 * ... * xn^in)/l^k is a monomial of f^(m-k)},
  where l is the leading monomial of f and 0 <= k <= m+1.
  Thus, the generated polynomials for the lattice are of the form
  g_i1,...,in,k = ((x1^i1 * x2^i2 * ... * xn^in)/l^k) * f^k * N^(m-k), for
  0 <= k <= m and x1^i1 * x2^i2 * ... * xn^in is an element of the set
  m_k - m_k+1. I.e., every new polynomial is a multiple of n and introduces
  exactly one new monomial to the lattice. In order to achieve better results
  for larger bounds, one can use a larger value of m. The maximum product of
  bounds possible should be about n^0.5. However, with more unknowns it is
  natural to achieve smaller bounds.

  Args:
    f: Multivariate polynomial modulus n.
    bounds: A list with the maximum values of the expected roots.
    m: A value that determines the size of the lattice.

  Returns:
    list r of roots, with -bounds[i] < r[i] < bounds[i], for the polynomial f if
      found, None otherwise.
  """
  n = f.get_modulus()
  fz = f.monic().set_domain(sympy.ZZ)
  xs = fz.gens
  # Let l be the leading monomial
  l = _get_monomials(fz)[0]
  # Define the sets M_k of monomials
  mks = []
  mons = _get_monomials(fz**m)
  for k in range(m + 1):
    fmk_mons = _get_monomials(fz**(m - k))
    mk = {mon for mon in mons if mon // l**k in fmk_mons}
    mks.append(mk)
  mks.append(set())
  # Define the shift polynomials
  pols = []
  for k in range(m + 1):
    diffs = mks[k] - mks[k + 1]
    g = fz**k * n**(m - k)
    for mon in diffs:
      pols.append((mon // l**k) * g)
  dim = len(pols)

  # create the lattice using the coefficients
  lat = [[0] * dim for _ in range(dim)]
  params = [sympy.Poly(xs[i] * bounds[i]) for i in range(len(xs))]
  for i in range(dim):
    pol = pols[i]
    for v in range(len(xs)):
      pol = sympy.compose(pol, params[v], xs[v])
    pol = sympy.Poly(pol, *xs)
    lat[i] = [pol.coeff_monomial(mons[j].as_expr()) for j in range(dim)]

  lat = lll.reduce(lat)

  # reconstruct polynomials
  for i in range(dim):
    for j in range(dim):
      lat[i][j] = gmpy.mpz(lat[i][j]) // int(sympy.Poly(mons[j], *xs)(*bounds))
  a = [lat[i][:-1] for i in range(dim - 1)]
  b = [-lat[i][-1] for i in range(dim - 1)]
  solutions = linalg_util.solve_right(a, b)
  if not solutions:
    return None
  pols = [mons[j] - int(solutions[j]) for j in range(len(solutions))]
  # TODO(pedroysb): Is there a better way to solve this without using sympy? For
  # very complex polynomials/monomials this may take a while...
  for roots in sympy.solve(pols, *xs, check=False, manual=True):
    if int(f(*roots)) % n == 0:
      return list(roots)
  return None
