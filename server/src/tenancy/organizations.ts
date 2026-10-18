import { INVITATION_EXPIRES_IN_SECONDS } from "./auth";
import { invitation, organization } from "../platform/db/schema";
import { HttpError, isUniqueViolation } from "../platform/http";
import { invitationEmail } from "./invitation-email";
import { ORG_ADMIN_ROLE } from "./permissions";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

export interface OrganizationsDeps {
  unitOfWork: UnitOfWork;
  /** Where users open the web UI, for the link in invitation emails. */
  webURL: string;
}

export interface Organizations {
  /**
   * Creates an Organization and invites its first Organization Administrator, as one audited change. Throws a 409
   * when the slug is taken, leaving no trace.
   *
   * This is the platform's own write rather than a Better Auth call: Better Auth's create-organization makes its
   * caller a member, and a Platform Operator sees inside an Organization only if explicitly invited into it. So
   * the invitation row is written here too, in the shape Better Auth accepts when the invitee accepts it.
   */
  create(
    operator: Actor,
    input: { name: string; slug: string; adminEmail: string },
  ): Promise<{ id: string; invitationId: string }>;
}

export function createOrganizations({ unitOfWork, webURL }: OrganizationsDeps): Organizations {
  return {
    async create(operator, { name, slug, adminEmail }) {
      const id = crypto.randomUUID();
      const invitationId = crypto.randomUUID();
      const email = adminEmail.toLowerCase();
      try {
        await unitOfWork.run(operator, async (tx, change) => {
          await tx.insert(organization).values({ id, name, slug, createdAt: change.occurredAt });
          await tx.insert(invitation).values({
            id: invitationId,
            organizationId: id,
            email,
            role: ORG_ADMIN_ROLE,
            status: "pending",
            // Better Auth judges expiry against the real time, not the unit of work's clock.
            expiresAt: new Date(Date.now() + INVITATION_EXPIRES_IN_SECONDS * 1000),
            createdAt: change.occurredAt,
            inviterId: operator.id,
          });
          await change.audit({
            organizationId: id,
            action: "organization.created",
            target: { type: "organization", id },
            detail: { slug, firstAdministrator: email },
          });
          change.mail(invitationEmail(webURL, { to: adminEmail, invitationId, organizationName: name, firstAdministrator: true }));
        });
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, "slug already in use");
        throw err;
      }
      return { id, invitationId };
    },
  };
}
