/// Implementation of Poly1305 function heavily inspired by the following [this implementation in C](https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-32.h)
/// referred to as "Donna". Further reference to [this](https://loup-vaillant.fr/tutorials/poly1305-design) article was used to formulate the multiplication loop.

const BITMASK: u32 = 0x03ffffff;
const CARRY: u32 = 26;

#[derive(Debug)]
pub(crate) struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    acc: [u32; 5],
}

impl Poly1305 {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        // taken from donna. assigns R to a 26-bit 5-limb number while simultaneously 'clamping' R
        let r0 = u32::from_le_bytes(key[0..4].try_into().expect("Valid subset of 32.")) & 0x3ffffff;
        let r1 = u32::from_le_bytes(key[3..7].try_into().expect("Valid subset of 32.")) >> 2 & 0x03ffff03;
        let r2 = u32::from_le_bytes(key[6..10].try_into().expect("Valid subset of 32.")) >> 4 & 0x03ffc0ff;
        let r3 = u32::from_le_bytes(key[9..13].try_into().expect("Valid subset of 32.")) >> 6 & 0x03f03fff;
        let r4 = u32::from_le_bytes(key[12..16].try_into().expect("Valid subset of 32.")) >> 8 & 0x000fffff;
        let r = [r0, r1, r2, r3, r4];
        let s0 = u32::from_le_bytes(key[16..20].try_into().expect("Valid subset of 32."));
        let s1 = u32::from_le_bytes(key[20..24].try_into().expect("Valid subset of 32."));
        let s2 = u32::from_le_bytes(key[24..28].try_into().expect("Valid subset of 32."));
        let s3 = u32::from_le_bytes(key[28..32].try_into().expect("Valid subset of 32."));
        let s = [s0, s1, s2, s3];
        let acc = [0; 5];
        Poly1305 { r, s, acc }
    }

    pub(crate) fn add(&mut self, message: &[u8]) {
        let mut i = 0;
        while i < message.len() / 16 {
            let msg_slice = prepare_padded_message_slice(&message[i * 16..(i+1) * 16], false);
            for (i, b) in msg_slice.iter().enumerate() {
                self.acc[i] += *b;
            }
            self.r_times_a();
            i += 1;
        }
        if message.len() % 16 > 0 {
            let msg_slice = prepare_padded_message_slice(&message[i * 16..], true);
            for (i, b) in msg_slice.iter().enumerate() {
                self.acc[i] += *b;
            }
            self.r_times_a();
        }
    }

    pub(crate) fn tag(&mut self) -> [u8; 16] {
        // carry and mask
        for i in 1..4 {
            self.acc[i+1] += self.acc[i] >> CARRY;
        }
        self.acc[0] += (self.acc[4] >> CARRY) * 5;
        self.acc[1] += self.acc[0] >> CARRY;
        for i in 0..self.acc.len() {
            self.acc[i] &= BITMASK;
        }
        // reduce
        let mut t = self.acc;
        t[0] += 5;
        t[4]  = t[4].wrapping_sub(1 << CARRY);
        for i in 0..3 {
            t[i+1] += t[i] >> CARRY;
        }
        t[4]  = t[4].wrapping_add(t[3] >> CARRY);
        for t in t.iter_mut().take(4) {
            *t &= BITMASK;
        }
        // convert acc to a 4 item array
        let mask = (t[4] >> 31).wrapping_sub(1);
        for (i, t) in t.iter().enumerate().take(self.acc.len()) {
            self.acc[i] = t & mask | self.acc[i] & !mask;
        }
        // voodoo from donna to convert to [u32; 4]
        let a0 = self.acc[0] | self.acc[1] << 26;
        let a1 = self.acc[1] >> 6 | self.acc[2] << 20;
        let a2 = self.acc[2] >> 12 | self.acc[3] << 14;
        let a3 = self.acc[3] >> 18 | self.acc[4] << 8;
        let a = [a0, a1, a2, a3];
        // a + s
        let mut tag : [u64; 4] = [0; 4];
        for i in 0..4 {
            tag[i] = a[i] as u64 + self.s[i] as u64;
        }
        //carry
        for i in 0..3 {
            tag[i + 1] += tag[i] >> 32;
        }
        // return the 16 least significant bytes
        let mut ret: [u8; 16] = [0; 16];
        for i in 0..tag.len() {
            let bytes = (tag[i] as u32).to_le_bytes();
            ret[i * 4..(i+1) * 4].copy_from_slice(&bytes);
        }
        ret
    }

    fn r_times_a(&mut self) {
        // multiply and reduce
        // while this looks complicated, it is a variation of schoolbook multiplication, 
        // described well in an article here: https://loup-vaillant.fr/tutorials/poly1305-design
        let mut t = [0; 5];
        for i in 0..5 {
            for j in 0..5 {
                let modulus: u64 = if i > j {
                    5
                } else {
                    1
                };
                let start = (5 - i) % 5;
                t[j] += modulus * self.r[i] as u64 * self.acc[(start + j) % 5] as u64;
            }
        }
        // carry
        for i in 0..4 {
            t[i + 1] += t[i] >> CARRY;
        }
        // mask
        for (i, t) in t.iter().enumerate().take(self.acc.len()) {
            self.acc[i] = *t as u32 & BITMASK;
        }
        // carry and mask first limb
        self.acc[0] += (t[4] >> CARRY) as u32 * 5;
        self.acc[1] += self.acc[0] >> CARRY;
        self.acc[0] &= BITMASK;
    }
}

fn prepare_padded_message_slice(msg: &[u8], is_last: bool) -> [u32; 5] {
    let hi_bit: u32 = if is_last {
        0
    } else {
        1 << 24
    };
    let mut fmt_msg = [0u8; 17];
    fmt_msg[..msg.len()].clone_from_slice(msg);
    fmt_msg[16] = 0x01;
    let m0 = u32::from_le_bytes(fmt_msg[0..4].try_into().expect("Valid subset of 32.")) & BITMASK;
    let m1 = u32::from_le_bytes(fmt_msg[3..7].try_into().expect("Valid subset of 32.")) >> 2 & BITMASK;
    let m2 = u32::from_le_bytes(fmt_msg[6..10].try_into().expect("Valid subset of 32.")) >> 4 & BITMASK;
    let m3 = u32::from_le_bytes(fmt_msg[9..13].try_into().expect("Valid subset of 32.")) >> 6 & BITMASK;
    let m4: u32 = if is_last {
        u32::from_le_bytes(fmt_msg[13..17].try_into().expect("Valid subset of 32.")) | hi_bit
    } else {
        u32::from_le_bytes(fmt_msg[12..16].try_into().expect("Valid subset of 32.")) >> 8 | hi_bit
    };
    [m0, m1, m2, m3, m4]
}

fn _print_acc(num: &[u32; 5]) {
    let a0 = num[0] | num[1] << 26;
    let a1 = num[1] >> 6 | num[2] << 20;
    let a2 = num[2] >> 12 | num[3] << 14;
    let a3 = num[3] >> 18 | num[4] << 8;
    let a = [a0, a1, a2, a3];
    let mut ret: [u8; 16] = [0; 16];
    for i in 0..a.len() {
        let bytes = a[i].to_le_bytes();
        ret[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    ret.reverse();
    // println!("{:?}{}", num[0].to_le_bytes()[3], hex::encode(ret));
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     // fails to shortcut encryption and decryption.
//     #[test]
//     fn test_none_message() {
//         let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
//         let key = key.as_slice().try_into().unwrap();
//         let mut poly = Poly1305::new(key);
//         let message = b"Cryptographic Forum Research Group";
//         poly.add(message);
//         let tag = poly.tag();
//         assert_eq!("a8061dc1305136c6c22b8baf0c0127a9",hex::encode(tag));
//     }
// }       