// LPC/LSF polynomial decomposition follows the SILK A2NLSF algorithm.
// Roots are bracketed in the angular domain and refined in f64.
pub fn lpc_to_nlsf(a: &[f64]) -> Vec<i16> {
    use std::f64::consts::PI;
    let half = a.len() / 2;
    let mut p = vec![0.; half + 1];
    let mut q = vec![0.; half + 1];
    p[half] = 1.;
    q[half] = 1.;
    for k in 0..half {
        p[k] = -a[half - k - 1] - a[half + k];
        q[k] = -a[half - k - 1] + a[half + k];
    }
    for k in (1..=half).rev() {
        p[k - 1] -= p[k];
        q[k - 1] += q[k];
    }
    for k in 2..=half {
        for n in (k + 1..=half).rev() {
            p[n - 2] -= p[n];
            q[n - 2] -= q[n];
        }
        p[k - 2] -= 2. * p[k];
        q[k - 2] -= 2. * q[k];
    }
    let evaluate = |polynomial: &[f64], angle: f64| {
        let x = 2. * angle.cos();
        polynomial
            .iter()
            .rev()
            .fold(0., |value, &coefficient| value * x + coefficient)
    };
    let step = PI / 1024.;
    let mut start = 1e-10;
    let mut out = Vec::with_capacity(a.len());
    for root in 0..a.len() {
        let polynomial = if root % 2 == 0 { &p } else { &q };
        let mut low = start;
        let mut ylow = evaluate(polynomial, low);
        let mut high = ((low / step).floor() + 1.) * step;
        let mut found = false;
        while high <= PI + 1e-10 {
            let yhigh = evaluate(polynomial, high.min(PI));
            if ylow * yhigh <= 0. {
                for _ in 0..40 {
                    let middle = (low + high) / 2.;
                    let y = evaluate(polynomial, middle);
                    if ylow * y <= 0. {
                        high = middle;
                    } else {
                        low = middle;
                        ylow = y;
                    }
                }
                let angle = (low + high) / 2.;
                out.push((angle / PI * 32768.).round().clamp(0., 32767.) as i16);
                start = angle + 1e-10;
                found = true;
                break;
            }
            low = high;
            ylow = yhigh;
            high += step;
        }
        if !found {
            return (1..=a.len())
                .map(|i| (i * 32768 / (a.len() + 1)) as i16)
                .collect();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn zero_predictor_has_evenly_spaced_spectral_roots() {
        for order in [10, 16] {
            let roots = super::lpc_to_nlsf(&vec![0.; order]);
            for (i, root) in roots.into_iter().enumerate() {
                let expected = (i + 1) as f64 * 32768. / (order + 1) as f64;
                assert!((root as f64 - expected).abs() < 1.);
            }
        }
    }
}
