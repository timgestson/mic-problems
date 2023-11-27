pub mod oblivious_transfer;

fn main() {
    let mut rng = ark_std::test_rng();
    oblivious_transfer::oblivious_transfer(
        &mut rng,
        b"Super secret message 1".to_vec(),
        b"Super secret message 2".to_vec(),
        false,
    );
    oblivious_transfer::oblivious_transfer(
        &mut rng,
        b"Super secret message 1".to_vec(),
        b"Super secret message 2".to_vec(),
        true,
    );
}
