#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[derive(Debug)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() >= 5 && key.len() <= 256);

        // Initialize the state array.
        let mut s = [0; 256];

        // Cipher state identity permutation.
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }

        // Process for 256 iterations, get starting cipher state permutation
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Rc4 { s, i: 0, j: 0 }
    }

    pub fn prga_next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize]
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b ^= self.prga_next();
        }
    }
}

impl Rc4 {
    pub fn apply_keystream_static(key: &[u8], data: &mut [u8]) {
        let mut rc4 = Rc4::new(key);
        rc4.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    const KEY: [u8; 16] = [
            0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
            0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
        ];

    #[rustfmt::skip]
    const PLAINTEXT : [u8;12] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
        0x72, 0x6c, 0x64, 0x21,
    ]; // "Hello World!"

    #[test]
    fn sanity_check_static_api() {
        let mut msg = PLAINTEXT.clone();

        // Encrypt in-place
        Rc4::apply_keystream_static(&KEY, &mut msg);
        assert_ne!(msg, PLAINTEXT);

        // Decrypt in-place
        Rc4::apply_keystream_static(&KEY, &mut msg);
        assert_eq!(msg, PLAINTEXT);
    }

    #[test]
    fn test_apply_keystream() {
        let mut msg = PLAINTEXT.clone();
        let mut rc4 = Rc4::new(&KEY);

        // Encrypt in-place
        rc4.apply_keystream(&mut msg);
        assert_ne!(msg, PLAINTEXT);

        let mut rc4 = Rc4::new(&KEY);
        // Decrypt in-place
        rc4.apply_keystream(&mut msg);
        assert_eq!(msg, PLAINTEXT);
    }

    #[test]
    fn ietf_40_bit_key_first_4_vectors() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut out_buf = [0u8; 272];

        #[rustfmt::skip]
        const TEST_STREAM_0: [u8; 16] = [
            0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
        ];

        #[rustfmt::skip]
        const TEST_STREAM_16: [u8; 16] = [
            0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5,
            0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19,
        ];

        #[rustfmt::skip]
        const TEST_STREAM_240: [u8; 16] = [
            0x28, 0xcb, 0x11, 0x32, 0xc9, 0x6c, 0xe2, 0x86,
            0x42, 0x1d, 0xca, 0xad, 0xb8, 0xb6, 0x9e, 0xae,
        ];

        #[rustfmt::skip]
        const TEST_STREAM_256: [u8; 16] = [
            0x1c, 0xfc, 0xf6, 0x2b, 0x03, 0xed, 0xdb, 0x64,
            0x1d, 0x77, 0xdf, 0xcf, 0x7f, 0x8d, 0x8c, 0x93,
        ];

        Rc4::apply_keystream_static(&key, &mut out_buf);

        const OFFSETS: [usize; 4] = [0, 16, 240, 256];
        const TESTS: [[u8; 16]; 4] = [
            TEST_STREAM_0,
            TEST_STREAM_16,
            TEST_STREAM_240,
            TEST_STREAM_256,
        ];

        for (offset, test) in OFFSETS.iter().zip(TESTS.iter()) {
            assert_eq!(&out_buf[*offset..*offset + 16], test);
        }

    }
}
