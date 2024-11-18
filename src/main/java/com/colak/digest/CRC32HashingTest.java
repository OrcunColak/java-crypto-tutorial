package com.colak.digest;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.zip.CRC32;

@Slf4j
@UtilityClass
public class CRC32HashingTest {

    public static void main() {
        String input = "password";
        String hash = hash(input);
        log.info("CRC32 Hash: {}", hash);
    }

    private static String hash(String input) {
        CRC32 crc = new CRC32();
        crc.update(input.getBytes());
        long checksum = crc.getValue();
        return Long.toHexString(checksum);
    }
}
