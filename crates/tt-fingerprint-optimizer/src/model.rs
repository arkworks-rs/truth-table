//! Fitting the prover cost model to measured points.
//!
//! The model itself — [`Shape`], [`terms`] and [`CostModel`] — lives in the
//! encoder crate, because the prover uses it at plan time to choose the
//! bins a pre-filter tests ([`arithmetic::fingerprint::cost::select_bins`]).
//! This module owns the offline side: measuring a query's shape over a
//! corpus and fitting the coefficients to whole-prove times (`tt-fp-opt
//! fit`, fed by the `tt-fp-calibrate` binary). The model is linear in the
//! coefficients, so a non-negative least-squares fit recovers them.

pub use arithmetic::fingerprint::cost::{CostModel, NUM_TERMS, Shape, TERMS, terms};
use arithmetic::fingerprint::{FingerprintScheme, FpMask, is_subset, touched_limbs};
use rayon::prelude::*;

use crate::corpus::{Corpus, like_matches};

/// The shape of `%factors%` over a corpus when the pre-filter tests the
/// bins of `phi` (none when `phi` is empty). `fingerprints` are the corpus
/// rows' fingerprints under `scheme`.
pub fn measure_shape(
    corpus: &Corpus,
    scheme: &FingerprintScheme,
    fingerprints: &[FpMask],
    factors: &[Vec<u8>],
    phi: &FpMask,
) -> Shape {
    let _ = scheme;
    let touched = touched_limbs(phi).len();
    let (survivors, survivor_chars, matches) = corpus
        .strings
        .par_iter()
        .zip(fingerprints)
        .map(|(s, fp)| {
            let survives = touched == 0 || is_subset(phi, fp);
            (
                usize::from(survives),
                if survives { s.len() } else { 0 },
                usize::from(like_matches(s, factors)),
            )
        })
        .reduce(|| (0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
    Shape {
        rows: corpus.len(),
        chars: corpus.strings.iter().map(Vec::len).sum::<usize>() as f64,
        survivors,
        survivor_chars: survivor_chars as f64,
        matches,
        touched_limbs: touched,
        literal_len: factors.iter().map(Vec::len).sum(),
        factors: factors.len(),
    }
}

/// Non-negative least squares over measured `(shape, seconds)` points.
pub fn fit(points: &[(Shape, f64)]) -> CostModel {
    fit_with_fixed(points, &[])
}

/// [`fit`] with some coefficients held at measured values: `fixed` is
/// `(term index, seconds per unit)`. Their contribution is taken out of
/// the targets and the remaining terms are fitted.
pub fn fit_with_fixed(points: &[(Shape, f64)], fixed: &[(usize, f64)]) -> CostModel {
    let mut rows: Vec<[f64; NUM_TERMS]> = points.iter().map(|(s, _)| terms(s)).collect();
    let mut y: Vec<f64> = points.iter().map(|&(_, t)| t).collect();
    for (row, target) in rows.iter_mut().zip(&mut y) {
        for &(term, value) in fixed {
            *target -= value * row[term];
            row[term] = 0.0;
        }
    }
    let mut coefficients = nnls(&rows, &y);
    for &(term, value) in fixed {
        coefficients[term] = value;
    }
    CostModel { coefficients }
}

/// Each point's cost under a model fitted without that point.
pub fn leave_one_out(points: &[(Shape, f64)], fixed: &[(usize, f64)]) -> Vec<f64> {
    (0..points.len())
        .map(|i| {
            let rest: Vec<_> = points
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, p)| *p)
                .collect();
            fit_with_fixed(&rest, fixed).cost(&points[i].0)
        })
        .collect()
}

/// Lawson–Hanson non-negative least squares: `argmin ‖A x − y‖, x ≥ 0`.
fn nnls(a: &[[f64; NUM_TERMS]], y: &[f64]) -> [f64; NUM_TERMS] {
    // Columns are scaled to unit norm so domains of 2^23 and indicator
    // terms share one numeric range.
    let scale: Vec<f64> = (0..NUM_TERMS)
        .map(|j| {
            let norm = a.iter().map(|row| row[j] * row[j]).sum::<f64>().sqrt();
            if norm > 0.0 { norm } else { 1.0 }
        })
        .collect();
    let col = |j: usize| -> Vec<f64> { a.iter().map(|row| row[j] / scale[j]).collect() };
    let cols: Vec<Vec<f64>> = (0..NUM_TERMS).map(col).collect();
    let n = a.len();
    let residual = |x: &[f64]| -> Vec<f64> {
        (0..n)
            .map(|i| y[i] - (0..NUM_TERMS).map(|j| cols[j][i] * x[j]).sum::<f64>())
            .collect()
    };
    let gradient = |r: &[f64]| -> Vec<f64> {
        (0..NUM_TERMS)
            .map(|j| cols[j].iter().zip(r).map(|(c, r)| c * r).sum())
            .collect()
    };
    // Unconstrained least squares on the passive set.
    let solve = |passive: &[usize]| -> Vec<f64> {
        let p = passive.len();
        let mut m = vec![vec![0.0; p + 1]; p];
        for (r, &i) in passive.iter().enumerate() {
            for (c, &j) in passive.iter().enumerate() {
                m[r][c] = cols[i].iter().zip(&cols[j]).map(|(a, b)| a * b).sum();
            }
            m[r][p] = cols[i].iter().zip(y).map(|(a, b)| a * b).sum();
        }
        // Gaussian elimination with partial pivoting (tiny ridge for
        // collinear terms).
        for (r, row) in m.iter_mut().enumerate() {
            row[r] += 1e-12;
        }
        for c in 0..p {
            let pivot = (c..p)
                .max_by(|&a, &b| m[a][c].abs().total_cmp(&m[b][c].abs()))
                .unwrap();
            m.swap(c, pivot);
            let pivot_row = m[c].clone();
            if pivot_row[c] == 0.0 {
                continue;
            }
            for (r, row) in m.iter_mut().enumerate() {
                if r != c {
                    let f = row[c] / pivot_row[c];
                    for (dst, src) in row[c..].iter_mut().zip(&pivot_row[c..]) {
                        *dst -= f * src;
                    }
                }
            }
        }
        (0..p)
            .map(|r| {
                if m[r][r] != 0.0 {
                    m[r][p] / m[r][r]
                } else {
                    0.0
                }
            })
            .collect()
    };

    let mut x = vec![0.0; NUM_TERMS];
    let mut passive: Vec<usize> = Vec::new();
    for _ in 0..3 * NUM_TERMS {
        let w = gradient(&residual(&x));
        let candidate = (0..NUM_TERMS)
            .filter(|j| !passive.contains(j))
            .max_by(|&a, &b| w[a].total_cmp(&w[b]));
        let Some(j) = candidate.filter(|&j| w[j] > 1e-10) else {
            break;
        };
        passive.push(j);
        loop {
            let z = solve(&passive);
            if z.iter().all(|&v| v > 0.0) {
                for (&i, &v) in passive.iter().zip(&z) {
                    x[i] = v;
                }
                break;
            }
            // Step toward z until a coefficient hits zero, drop it.
            let alpha = passive
                .iter()
                .zip(&z)
                .filter(|&(_, &v)| v <= 0.0)
                .map(|(&i, &v)| x[i] / (x[i] - v))
                .fold(f64::INFINITY, f64::min);
            for (&i, &v) in passive.iter().zip(&z) {
                x[i] += alpha * (v - x[i]);
            }
            passive.retain(|&i| x[i] > 1e-12);
            for (i, xi) in x.iter_mut().enumerate() {
                if !passive.contains(&i) {
                    *xi = 0.0;
                }
            }
            if passive.is_empty() {
                break;
            }
        }
    }
    std::array::from_fn(|j| x[j] / scale[j])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(survivors: usize, matches: usize, touched: usize) -> Shape {
        Shape {
            rows: 300_000,
            chars: 8.0e6,
            survivors,
            survivor_chars: survivors as f64 * 26.5,
            matches,
            touched_limbs: touched,
            literal_len: 4,
            factors: 1,
        }
    }

    #[test]
    fn nnls_recovers_non_negative_coefficients() {
        let truth = CostModel {
            coefficients: [
                40.0, 1.0, 0.4, 2.0, 1e-4, 2e-5, 2e-5, 1e-5, 3e-5, 1.5, 1e-3, 1e-6, 1e-4, 2e-5,
                5e-5,
            ],
        };
        let mut points = Vec::new();
        for &s in &[500, 3_000, 20_000, 70_000, 150_000, 300_000] {
            for &m in &[0, s / 2, s * 9 / 10] {
                for &t in &[0, 1, 3, 6] {
                    for &(len, factors) in &[(3, 1), (4, 2), (8, 3)] {
                        let mut sh = shape(if t == 0 { 300_000 } else { s }, m, t);
                        sh.literal_len = len;
                        sh.factors = factors;
                        points.push((sh, truth.cost(&sh)));
                    }
                }
            }
        }
        let fit = fit(&points);
        for (sh, y) in &points {
            assert!((fit.cost(sh) - y).abs() < 1e-3 * y.max(1.0), "{sh:?}");
        }
        assert!(fit.coefficients.iter().all(|&c| c >= 0.0));
        let restored = CostModel::from_toml_str(&fit.to_toml_string()).unwrap();
        assert_eq!(restored, fit);
        // Holding a coefficient at its true value leaves the rest recoverable.
        let pinned = fit_with_fixed(&points, &[(2, 0.4)]);
        assert_eq!(pinned.coefficients[2], 0.4);
        for (sh, y) in &points {
            assert!((pinned.cost(sh) - y).abs() < 1e-3 * y.max(1.0), "{sh:?}");
        }
    }
}
