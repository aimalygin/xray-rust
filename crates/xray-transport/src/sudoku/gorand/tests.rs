use super::*;

#[test]
fn draws_what_go_math_rand_draws() {
    // From Go 1.27.3: rand.New(rand.NewSource(seed)).Int63(), three times.
    for (seed, expected) in [
        (
            0,
            [
                8717895732742165505,
                2259404117704393152,
                6050128673802995827,
            ],
        ),
        (
            1,
            [
                5577006791947779410,
                8674665223082153551,
                6129484611666145821,
            ],
        ),
        (
            -1,
            [3644962268338389676, 550171362161912239, 3094056749125766625],
        ),
        (
            1 << 40,
            [
                5470237361722394362,
                6322525149314491254,
                1177463506020107830,
            ],
        ),
        (
            -987654321123,
            [
                1138484101124664527,
                3236619388243269326,
                1879649566847446321,
            ],
        ),
        // Seeds are taken modulo 2^31 - 1, where it gives 0, as Go does.
        (
            2147483647,
            [
                8717895732742165505,
                2259404117704393152,
                6050128673802995827,
            ],
        ),
    ] {
        let mut rng = GoRand::new(seed);
        assert_eq!([rng.int63(), rng.int63(), rng.int63()], expected, "{seed}");
    }
}

#[test]
fn shuffles_as_go_math_rand_shuffles() {
    // Go 1.27.3, seeded from the SHA-256 of "synthetic-password".
    let mut order: Vec<usize> = (0..288).collect();
    GoRand::new(-2887381652307062414).shuffle(&mut order);
    assert_eq!(
        order[..16],
        [183, 197, 61, 33, 174, 101, 227, 165, 257, 247, 237, 137, 224, 234, 37, 189]
    );
    assert_eq!((order[100], order[287]), (164, 246));
}
