// The Enrollment Validator contract, run against the test kind and its service double, so that the contract itself is
// kept honest; a real kind (Intune) runs it unchanged against its own double.
import { DOUBLE_SECRET, ValidatorDouble } from "./support/enrollment-validator-double";
import { enrollmentValidatorContract } from "./support/enrollment-validator-contract";

const double = new ValidatorDouble();

enrollmentValidatorContract("the test kind", () => {
  double.reset();
  return {
    kind: double.kind(),
    settings: { tenant: "contoso" },
    secret: DOUBLE_SECRET,
    wrongSecret: "not-the-secret",
    service: {
      allow: () => void (double.refusing = null),
      refuse: () => void (double.refusing = "ChallengeExpired"),
      setUnreachable: (unreachable) => void (double.unreachable = unreachable),
      validated: () => double.validations.map((v) => v.transactionId),
      issued: () => double.issued.map((i) => ({ transactionId: i.request.transactionId, serial: i.certificate.serial })),
      failed: () => double.failed.map((f) => f.request.transactionId),
      queueRevocation: (serial, issuer) => double.queueRevocation("contoso", serial, issuer),
      revocationOutcomes: () => double.reports.flatMap((r) => r.outcomes.map((o) => o.outcome)),
    },
  };
});
