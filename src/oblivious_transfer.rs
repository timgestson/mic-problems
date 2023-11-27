use ark_curve25519::Curve25519Config;
use ark_curve25519::{EdwardsProjective as G, Fr as Scalar};
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Div, ops::Mul, UniformRand};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha8;
use rand::Rng;

// Key Derivation algo inspired by https://github.com/cronokirby/yao-gc/blob/main/src/ot.rs
// and this blog post https://cronokirby.com/posts/2021/06/introducing_nimotsu/
const DERIVE_KEY_FROM_POINT_CONTEXT: &str = "Oblivious Transfer 11-16-2023";

fn kdf(point: &G) -> [u8; 32] {
    let mut compressed_bytes = Vec::new();
    point.serialize_compressed(&mut compressed_bytes).unwrap();
    blake3::derive_key(DERIVE_KEY_FROM_POINT_CONTEXT, &compressed_bytes)
}

fn encrypt_once(key: &[u8; 32], data: &mut [u8]) {
    let nonce = [0; 12];
    let mut cipher = ChaCha8::new(key.into(), &nonce.into());
    cipher.apply_keystream(data);
}

fn decrypt(key: &[u8; 32], data: &mut [u8]) {
    encrypt_once(key, data);
}

// Alice is the sender in the 2 party OB protocol
struct Alice {
    a: Scalar,
    A: G,
    B: Option<G>,
    message1: Vec<u8>,
    message2: Vec<u8>,
}

impl Alice {
    fn new(rng: &mut impl Rng, message1: Vec<u8>, message2: Vec<u8>) -> Alice {
        let a = Scalar::rand(rng);
        let A = G::generator() * a;
        Alice {
            a,
            A,
            B: None,
            message1,
            message2,
        }
    }

    fn derive_and_encrypt(&mut self, B: G) {
        self.B = Some(B);
        let k0point = B * self.a;
        let k1point = (B - self.A) * self.a;

        let k0 = kdf(&k0point);
        let k1 = kdf(&k1point);

        encrypt_once(&k0, &mut self.message1);
        encrypt_once(&k1, &mut self.message2);
    }
}

// Bob is the receiver in the 2 party OB protocol
struct Bob {
    b: Scalar,
    B: G,
    A: G,
}

impl Bob {
    fn new(rng: &mut impl Rng, A: G, c: bool) -> Bob {
        let b = Scalar::rand(rng);
        let generator = G::generator();
        let B = match c {
            true => generator * b + A,
            false => generator * b,
        };
        Bob { b, B, A }
    }

    fn decrypt(&self, mut message1: Vec<u8>, mut message2: Vec<u8>) {
        let decryptPoint = self.A * self.b;
        let decryptKey = kdf(&decryptPoint);

        decrypt(&decryptKey, &mut message1);
        decrypt(&decryptKey, &mut message2);

        println!("{}", String::from_utf8_lossy(&message1));
        println!("{}", String::from_utf8_lossy(&message2));
    }
}

pub fn oblivious_transfer(rng: &mut impl Rng, message1: Vec<u8>, message2: Vec<u8>, c: bool) {
    // Alice creates secret a and A = g^a
    let mut alice = Alice::new(rng, message1.clone(), message2.clone());
    // Alice sends Bob A and Bob generates B based on the bit c
    let mut bob = Bob::new(rng, alice.A.clone(), c);

    // Bob sends alice B and Alice encrypts the 2 messages obliviously
    alice.derive_and_encrypt(bob.B.clone());
    // Bob tries to decrypt both messages with key he can derive from A^b
    bob.decrypt(alice.message1.clone(), alice.message2.clone());
}
