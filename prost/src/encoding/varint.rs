use core::{cmp::min, num::NonZeroU64};

use ::bytes::{Buf, BufMut};

use crate::DecodeError;

/// Encodes an integer value into LEB128 variable length format, and writes it to the buffer.
/// The buffer must have enough remaining space (maximum 10 bytes).
#[inline]
pub fn encode_varint(mut value: u64, buf: &mut impl BufMut) {
    // Varints are never more than 10 bytes
    for _ in 0..10 {
        if value < 0x80 {
            buf.put_u8(value as u8);
            break;
        } else {
            buf.put_u8(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
    }
}

/// Returns the encoded length of the value in LEB128 variable length format.
/// The returned value will be between 1 and 10, inclusive.
#[inline]
pub const fn encoded_len_varint(value: u64) -> usize {
    // Based on [VarintSize64][1].
    // [1]: https://github.com/protocolbuffers/protobuf/blob/v28.3/src/google/protobuf/io/coded_stream.h#L1744-L1756
    // Safety: value | 1 is non-zero.
    let log2value = unsafe { NonZeroU64::new_unchecked(value | 1) }.ilog2();
    ((log2value * 9 + (64 + 9)) / 64) as usize
}

/// Decodes a LEB128-encoded variable length integer from the buffer.
#[inline]
pub fn decode_varint(buf: &mut impl Buf) -> Result<u64, DecodeError> {
    let bytes = buf.chunk();
    let len = bytes.len();
    if len == 0 {
        return Err(DecodeError::new("invalid varint"));
    }

    let byte = unsafe { *bytes.get_unchecked(0) };
    if byte < 0x80 {
        // 1 byte varint
        buf.advance(1);
        Ok(u64::from(byte))
    } else if len >= 10 || (len >= 8 && bytes[len - 1] < 0x80) {
        let first_8 = unsafe { bytes.as_ptr().cast::<u64>().read_unaligned() };
        // let first_4 = unsafe { bytes.as_ptr().cast::<u32>().read_unaligned() };

        let completions_in_first_8 = !first_8 & !0x7f7f7f7f7f7f7f7f;

        // let completions_in_first_4 = !first_4 & !0x7f7f7f7f;

        // specialise on size in a single jump

        return Ok(if completions_in_first_8 != 0 {
            // use 1 bytes unstead of 0x80 bytes
            let completions_in_first_8 = (completions_in_first_8 >> 7) & 0x0101010101010101;
            let completions_in_first_8: [u8; 8] = completions_in_first_8.to_ne_bytes();
            let completions_in_first_8: [bool; 8] =
                unsafe { std::mem::transmute(completions_in_first_8) };

            let first_8_masked = first_8 & 0x7f7f7f7f7f7f7f7f;

            let (value, advance) =
                decode_varint_8_or_less(first_8_masked.to_ne_bytes(), completions_in_first_8);
            buf.advance(advance);
            value
        } else {
            let first_4 = unsafe { bytes.as_ptr().cast::<u32>().read_unaligned() };
            let second_4 = unsafe { bytes.as_ptr().cast::<u32>().add(1).read_unaligned() };

            // 9 or 10 byte case

            // SAFETY: if len is 8, then bytes[7] was a completion and we would not take this branch
            let byte_9 = unsafe { *bytes.get_unchecked(8) };
            if byte_9 < 0x80 {
                buf.advance(9);
                decode_varint_9(first_4, second_4, byte_9)
            } else {
                // SAFETY: if len is 9, then byte_9 was a completion and we would not take this branch
                let byte_10 = unsafe { *bytes.get_unchecked(9) };

                if byte_10 > 0b00000001 {
                    // tenth byte cannot be a continuation, and if its over 1 then its a u64 overflow
                    return Err(DecodeError::new("invalid varint"));
                }

                buf.advance(10);
                decode_varint_10(first_4, second_4, byte_9, byte_10)
            }
        });
    } else if bytes[len - 1] < 0x80 {
        // len less than 8, terminating with a completion
        let (value, advance) = decode_varint_slice(bytes)?;
        buf.advance(advance);
        Ok(value)
    } else {
        // short slice that doesn't terminate with a completion, use the slow path that can tolerate this
        decode_varint_slow(buf)
    }
}

/// Decodes a LEB128-encoded variable length integer from the slice, returning the value and the
/// number of bytes read.
///
/// Based loosely on [`ReadVarint64FromArray`][1] with a varint overflow check from
/// [`ConsumeVarint`][2].
///
/// ## Safety
///
/// The caller must ensure that `bytes` is non-empty and either `bytes.len() >= 10` or the last
/// element in bytes is < `0x80`.
///
/// [1]: https://github.com/google/protobuf/blob/3.3.x/src/google/protobuf/io/coded_stream.cc#L365-L406
/// [2]: https://github.com/protocolbuffers/protobuf-go/blob/v1.27.1/encoding/protowire/wire.go#L358
#[inline]
fn decode_varint_slice(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    // Fully unrolled varint decoding loop. Splitting into 32-bit pieces gives better performance.

    // Use assertions to ensure memory safety, but it should always be optimized after inline.
    assert!(!bytes.is_empty());
    assert!(bytes.len() > 10 || bytes[bytes.len() - 1] < 0x80);

    let mut b: u8 = unsafe { *bytes.get_unchecked(0) };
    let mut part0: u32 = u32::from(b);
    if b < 0x80 {
        return Ok((u64::from(part0), 1));
    };
    part0 -= 0x80;
    b = unsafe { *bytes.get_unchecked(1) };
    part0 += u32::from(b) << 7;
    if b < 0x80 {
        return Ok((u64::from(part0), 2));
    };
    part0 -= 0x80 << 7;
    b = unsafe { *bytes.get_unchecked(2) };
    part0 += u32::from(b) << 14;
    if b < 0x80 {
        return Ok((u64::from(part0), 3));
    };
    part0 -= 0x80 << 14;
    b = unsafe { *bytes.get_unchecked(3) };
    part0 += u32::from(b) << 21;
    if b < 0x80 {
        return Ok((u64::from(part0), 4));
    };
    part0 -= 0x80 << 21;
    let value = u64::from(part0);

    b = unsafe { *bytes.get_unchecked(4) };
    let mut part1: u32 = u32::from(b);
    if b < 0x80 {
        return Ok((value + (u64::from(part1) << 28), 5));
    };
    part1 -= 0x80;
    b = unsafe { *bytes.get_unchecked(5) };
    part1 += u32::from(b) << 7;
    if b < 0x80 {
        return Ok((value + (u64::from(part1) << 28), 6));
    };
    part1 -= 0x80 << 7;
    b = unsafe { *bytes.get_unchecked(6) };
    part1 += u32::from(b) << 14;
    if b < 0x80 {
        return Ok((value + (u64::from(part1) << 28), 7));
    };
    part1 -= 0x80 << 14;
    b = unsafe { *bytes.get_unchecked(7) };
    part1 += u32::from(b) << 21;
    if b < 0x80 {
        return Ok((value + (u64::from(part1) << 28), 8));
    };
    part1 -= 0x80 << 21;
    let value = value + ((u64::from(part1)) << 28);

    b = unsafe { *bytes.get_unchecked(8) };
    let mut part2: u32 = u32::from(b);
    if b < 0x80 {
        return Ok((value + (u64::from(part2) << 56), 9));
    };
    part2 -= 0x80;
    b = unsafe { *bytes.get_unchecked(9) };
    part2 += u32::from(b) << 7;
    // Check for u64::MAX overflow. See [`ConsumeVarint`][1] for details.
    // [1]: https://github.com/protocolbuffers/protobuf-go/blob/v1.27.1/encoding/protowire/wire.go#L358
    if b < 0x02 {
        return Ok((value + (u64::from(part2) << 56), 10));
    };

    // We have overrun the maximum size of a varint (10 bytes) or the final byte caused an overflow.
    // Assume the data is corrupt.
    Err(DecodeError::new("invalid varint"))
}

#[inline(always)]
fn decode_varint_10(low: u32, high: u32, byte_9: u8, byte_10: u8) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
        | (((high & 0x00007f00) as u64) << 27)
        | (((high & 0x007f0000) as u64) << 26)
        | (((high & 0x7f000000) as u64) << 25)
        | (((byte_9 & 0x7f) as u64) << 56)
        | (((byte_10 & 0x01) as u64) << 63)
}

#[inline(always)]
fn decode_varint_9(low: u32, high: u32, byte_9: u8) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
        | (((high & 0x00007f00) as u64) << 27)
        | (((high & 0x007f0000) as u64) << 26)
        | (((high & 0x7f000000) as u64) << 25)
        | (((byte_9 & 0x7f) as u64) << 56)
}

#[inline(always)]
fn decode_varint_8(low: u32, high: u32) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
        | (((high & 0x00007f00) as u64) << 27)
        | (((high & 0x007f0000) as u64) << 26)
        | (((high & 0x7f000000) as u64) << 25)
}

fn decode_varint_8_or_less(uncompleted: [u8; 8], completions: [bool; 8]) -> (u64, usize) {
    // Extract bytes from the u64 using shifts and masks
    let mut part0: u32 = u32::from(uncompleted[0]);
    if completions[0] {
        return (u64::from(part0), 1);
    };

    part0 += u32::from(uncompleted[1]) << 7;
    if completions[1] {
        return (u64::from(part0), 2);
    };

    part0 += u32::from(uncompleted[2]) << 14;
    if completions[2] {
        return (u64::from(part0), 3);
    };

    part0 += u32::from(uncompleted[3]) << 21;
    if completions[3] {
        return (u64::from(part0), 4);
    };
    let value = u64::from(part0);

    let mut part1: u32 = u32::from(uncompleted[4]);
    if completions[4] {
        return (value + (u64::from(part1) << 28), 5);
    };

    part1 += u32::from(uncompleted[5]) << 7;
    if completions[5] {
        return (value + (u64::from(part1) << 28), 6);
    };

    part1 += u32::from(uncompleted[6]) << 14;
    if completions[6] {
        return (value + (u64::from(part1) << 28), 7);
    };

    part1 += u32::from(uncompleted[7]) << 21;
    return (value + (u64::from(part1) << 28), 8);
}

#[inline(always)]
fn decode_varint_7(low: u32, high: u32) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
        | (((high & 0x00007f00) as u64) << 27)
        | (((high & 0x007f0000) as u64) << 26)
}

#[inline(always)]
fn decode_varint_6(low: u32, high: u32) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
        | (((high & 0x00007f00) as u64) << 27)
}

#[inline(always)]
fn decode_varint_5(low: u32, high: u32) -> u64 {
    ((low & 0x0000007f) as u64)
        | (((low & 0x00007f00) >> 1) as u64)
        | (((low & 0x007f0000) >> 2) as u64)
        | (((low & 0x7f000000) >> 3) as u64)
        | (((high & 0x0000007f) as u64) << 28)
}

#[inline(always)]
fn decode_varint_4(x: u32) -> u64 {
    ((x & 0x0000007f) | ((x & 0x7f000000) >> 3) | ((x & 0x007f0000) >> 2) | ((x & 0x00007f00) >> 1))
        as u64
}

#[inline(always)]
fn decode_varint_3(x: u32) -> u64 {
    ((x & 0x0000007f) | ((x & 0x007f0000) >> 2) | ((x & 0x00007f00) >> 1)) as u64
}

#[inline(always)]
fn decode_varint_2(x: u32) -> u64 {
    ((x & 0x0000007f) | ((x & 0x00007f00) >> 1)) as u64
}

/// Decodes a LEB128-encoded variable length integer from the buffer, advancing the buffer as
/// necessary.
///
/// Contains a varint overflow check from [`ConsumeVarint`][1].
///
/// [1]: https://github.com/protocolbuffers/protobuf-go/blob/v1.27.1/encoding/protowire/wire.go#L358
#[inline(never)]
#[cold]
fn decode_varint_slow(buf: &mut impl Buf) -> Result<u64, DecodeError> {
    let mut value = 0;
    for count in 0..min(10, buf.remaining()) {
        let byte = buf.get_u8();
        value |= u64::from(byte & 0x7F) << (count * 7);
        if byte <= 0x7F {
            // Check for u64::MAX overflow. See [`ConsumeVarint`][1] for details.
            // [1]: https://github.com/protocolbuffers/protobuf-go/blob/v1.27.1/encoding/protowire/wire.go#L358
            if count == 9 && byte >= 0x02 {
                return Err(DecodeError::new("invalid varint"));
            } else {
                return Ok(value);
            }
        }
    }

    Err(DecodeError::new("invalid varint"))
}

#[cfg(test)]
mod test {
    use core::u64;

    use super::*;
    use proptest::proptest;

    proptest! {
        #[test]
        fn check_roundtrip(nums in proptest::collection::vec(proptest::num::u64::ANY, 0..16)) {

            let mut buf = Vec::with_capacity(1);
            for num in &nums {
                encode_varint(*num, &mut buf);
            }
            let mut slice = buf.as_slice();

            let mut out_nums = Vec::with_capacity(nums.len());
            while slice.has_remaining() {
                let num = decode_varint(&mut slice).unwrap();
                out_nums.push(num);
            }
            assert_eq!(out_nums, nums)
        }
    }

    #[test]
    fn varint() {
        fn check(value: u64, encoded: &[u8]) {
            // Small buffer.
            let mut buf = Vec::with_capacity(1);
            encode_varint(value, &mut buf);
            assert_eq!(buf, encoded);

            // Large buffer.
            let mut buf = Vec::with_capacity(100);
            encode_varint(value, &mut buf);
            assert_eq!(buf, encoded);

            assert_eq!(encoded_len_varint(value), encoded.len());

            // See: https://github.com/tokio-rs/prost/pull/1008 for copying reasoning.
            let mut encoded_copy = encoded;
            let roundtrip_value = decode_varint(&mut encoded_copy).expect("decoding failed");
            assert_eq!(value, roundtrip_value);

            let mut encoded_copy = encoded;
            let roundtrip_value =
                decode_varint_slow(&mut encoded_copy).expect("slow decoding failed");
            assert_eq!(value, roundtrip_value);
        }

        check(2u64.pow(0) - 1, &[0x00]);
        check(2u64.pow(0), &[0x01]);

        check(2u64.pow(7) - 1, &[0x7F]);
        check(2u64.pow(7), &[0x80, 0x01]);
        check(300, &[0xAC, 0x02]);

        check(2u64.pow(14) - 1, &[0xFF, 0x7F]);
        check(2u64.pow(14), &[0x80, 0x80, 0x01]);

        check(2u64.pow(21) - 1, &[0xFF, 0xFF, 0x7F]);
        check(2u64.pow(21), &[0x80, 0x80, 0x80, 0x01]);

        check(2u64.pow(28) - 1, &[0xFF, 0xFF, 0xFF, 0x7F]);
        check(2u64.pow(28), &[0x80, 0x80, 0x80, 0x80, 0x01]);

        check(2u64.pow(35) - 1, &[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        check(2u64.pow(35), &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);

        check(2u64.pow(42) - 1, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        check(2u64.pow(42), &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);

        check(
            2u64.pow(49) - 1,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        );
        check(
            2u64.pow(49),
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        );

        check(
            2u64.pow(56) - 1,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        );
        check(
            2u64.pow(56),
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        );

        check(
            2u64.pow(63) - 1,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        );
        check(
            2u64.pow(63),
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        );

        check(
            u64::MAX,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        );
    }

    const U64_MAX_PLUS_ONE: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];

    #[test]
    fn varint_overflow() {
        let mut copy = U64_MAX_PLUS_ONE;
        decode_varint(&mut copy).expect_err("decoding u64::MAX + 1 succeeded");
    }

    #[test]
    fn variant_slow_overflow() {
        let mut copy = U64_MAX_PLUS_ONE;
        decode_varint_slow(&mut copy).expect_err("slow decoding u64::MAX + 1 succeeded");
    }
}
