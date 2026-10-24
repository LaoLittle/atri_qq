use crate::tables_nlsf_vec::{
    NLSF_CB0_10_NDELTA_MIN_Q15, NLSF_CB0_10_ORDER, NLSF_CB0_10_Q15, NLSF_CB0_10_STAGE_NVEC,
    NLSF_CB0_16_NDELTA_MIN_Q15, NLSF_CB0_16_ORDER, NLSF_CB0_16_Q15, NLSF_CB0_16_STAGE_NVEC,
    NLSF_CB1_10_NDELTA_MIN_Q15, NLSF_CB1_10_ORDER, NLSF_CB1_10_Q15, NLSF_CB1_10_STAGE_NVEC,
    NLSF_CB1_16_NDELTA_MIN_Q15, NLSF_CB1_16_ORDER, NLSF_CB1_16_Q15, NLSF_CB1_16_STAGE_NVEC,
};

#[derive(Clone, Copy)]
pub enum NlsfCbKind {
    Cb0_10,
    Cb1_10,
    Cb0_16,
    Cb1_16,
}

fn stabilize(nlsf_q15: &mut [i32], ndelta_min_q15: &[i32]) {
    const MAX_LOOPS: usize = 20;
    let l = nlsf_q15.len();

    for _ in 0..MAX_LOOPS {
        let mut i_min = 0usize;
        let mut min_diff = nlsf_q15[0] - ndelta_min_q15[0];

        for i in 1..l {
            let diff = nlsf_q15[i] - (nlsf_q15[i - 1] + ndelta_min_q15[i]);
            if diff < min_diff {
                min_diff = diff;
                i_min = i;
            }
        }
        let last_diff = (1 << 15) - (nlsf_q15[l - 1] + ndelta_min_q15[l]);
        if last_diff < min_diff {
            min_diff = last_diff;
            i_min = l;
        }
        if min_diff >= 0 {
            return;
        }

        if i_min == 0 {
            nlsf_q15[0] = ndelta_min_q15[0];
        } else if i_min == l {
            nlsf_q15[l - 1] = (1 << 15) - ndelta_min_q15[l];
        } else {
            let mut min_center = 0i32;
            for &v in ndelta_min_q15.iter().take(i_min) {
                min_center += v;
            }
            min_center += ndelta_min_q15[i_min] >> 1;

            let mut max_center = 1 << 15;
            for k in (i_min + 1..=l).rev() {
                max_center -= ndelta_min_q15[k];
            }
            max_center -= ndelta_min_q15[i_min] - (ndelta_min_q15[i_min] >> 1);

            let mut center =
                ((nlsf_q15[i_min - 1] + nlsf_q15[i_min] + 1) >> 1).clamp(min_center, max_center);
            nlsf_q15[i_min - 1] = center - (ndelta_min_q15[i_min] >> 1);
            center = nlsf_q15[i_min - 1] + ndelta_min_q15[i_min];
            nlsf_q15[i_min] = center;
        }
    }

    nlsf_q15.sort_unstable();
    nlsf_q15[0] = nlsf_q15[0].max(ndelta_min_q15[0]);
    for i in 1..l {
        nlsf_q15[i] = nlsf_q15[i].max(nlsf_q15[i - 1] + ndelta_min_q15[i]);
    }
    nlsf_q15[l - 1] = nlsf_q15[l - 1].min((1 << 15) - ndelta_min_q15[l]);
    for i in (0..l - 1).rev() {
        nlsf_q15[i] = nlsf_q15[i].min(nlsf_q15[i + 1] - ndelta_min_q15[i + 1]);
    }
}

pub fn nlsf_msvq_decode(kind: NlsfCbKind, indices: &[usize]) -> Vec<i32> {
    let (order, stage_nvec, cb_q15, ndelta): (usize, &[usize], &[i16], &[i32]) = match kind {
        NlsfCbKind::Cb0_10 => (
            NLSF_CB0_10_ORDER,
            &NLSF_CB0_10_STAGE_NVEC,
            &NLSF_CB0_10_Q15,
            &NLSF_CB0_10_NDELTA_MIN_Q15,
        ),
        NlsfCbKind::Cb1_10 => (
            NLSF_CB1_10_ORDER,
            &NLSF_CB1_10_STAGE_NVEC,
            &NLSF_CB1_10_Q15,
            &NLSF_CB1_10_NDELTA_MIN_Q15,
        ),
        NlsfCbKind::Cb0_16 => (
            NLSF_CB0_16_ORDER,
            &NLSF_CB0_16_STAGE_NVEC,
            &NLSF_CB0_16_Q15,
            &NLSF_CB0_16_NDELTA_MIN_Q15,
        ),
        NlsfCbKind::Cb1_16 => (
            NLSF_CB1_16_ORDER,
            &NLSF_CB1_16_STAGE_NVEC,
            &NLSF_CB1_16_Q15,
            &NLSF_CB1_16_NDELTA_MIN_Q15,
        ),
    };

    let mut out = vec![0i32; order];
    let mut stage_base = 0usize;
    for (s, &nvec) in stage_nvec.iter().enumerate() {
        let ix = indices
            .get(s)
            .copied()
            .unwrap_or(0)
            .min(nvec.saturating_sub(1));
        let vec_base = (stage_base + ix) * order;
        for i in 0..order {
            out[i] += cb_q15[vec_base + i] as i32;
        }
        stage_base += nvec;
    }
    stabilize(&mut out, ndelta);
    out
}
