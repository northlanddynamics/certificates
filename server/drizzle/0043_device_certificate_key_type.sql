ALTER TABLE "device_certificate" ADD COLUMN "key_type" text;--> statement-breakpoint
-- Every Device Certificate so far certifies an RSA key of 2048, 3072 or 4096 bits, the only ones a profile allowed. Its
-- size is read from the certificate's subjectPublicKeyInfo: after the rsaEncryption algorithm identifier come the BIT
-- STRING and SEQUENCE headers (long form, 4 and 4 bytes, then the BIT STRING's unused-bits byte) and the modulus's
-- INTEGER header, whose two length bytes count the modulus with its leading zero byte. A certificate whose key is not
-- found is left without one, so that the NOT NULL below fails the migration rather than recording a wrong key type.
UPDATE "device_certificate" AS c SET "key_type" = 'rsa-' || ((get_byte(k.der, k.at + 23) * 256 + get_byte(k.der, k.at + 24) - 1) * 8)
FROM (
  SELECT "id", der, position('\x06092a864886f70d0101010500'::bytea IN der) AS at
  FROM (SELECT "id", decode(regexp_replace("certificate_pem", '-----[A-Z ]+-----|\s', '', 'g'), 'base64') AS der FROM "device_certificate") AS d
) AS k
WHERE c."id" = k."id" AND k.at > 0;--> statement-breakpoint
ALTER TABLE "device_certificate" ALTER COLUMN "key_type" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "device_certificate_weak_key_idx" ON "device_certificate" USING btree ("enrollment_profile_id") WHERE "device_certificate"."key_type" = 'rsa-1024';
