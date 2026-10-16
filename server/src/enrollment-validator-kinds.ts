// Every kind of Enrollment Validator the platform runs (enrollment-validator.ts). A new one is a module like intune.ts
// and an entry here. Tests give the app their own kinds instead (`AppDeps.enrollmentValidators`).
import type { EnrollmentValidators } from "./enrollment-validator";
import { intune } from "./intune";

export const ENROLLMENT_VALIDATOR_KINDS: EnrollmentValidators = { intune };
