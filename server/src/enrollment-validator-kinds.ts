// Every kind of Enrollment Validator the platform runs (enrollment-validator.ts). A new one is a module and an entry here.
// None yet: Intune is the first (`.scratch/device-enrollment/issues/04-intune-enrollment-validator.md`); tests give the
// app their own kinds instead (`AppDeps.enrollmentValidators`).
import type { EnrollmentValidators } from "./enrollment-validator";

export const ENROLLMENT_VALIDATOR_KINDS: EnrollmentValidators = {};
