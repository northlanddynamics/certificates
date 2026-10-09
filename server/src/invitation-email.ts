import type { Mail } from "./mailer";

/** The email that carries an invitation to its recipient; the one place its wording lives. */
export function invitationEmail(
  webURL: string,
  invitation: { to: string; invitationId: string; organizationName: string; firstAdministrator?: boolean },
): Mail {
  const { to, invitationId, organizationName, firstAdministrator = false } = invitation;
  return {
    to,
    subject: firstAdministrator
      ? `You are invited to administer ${organizationName}`
      : `You are invited to join ${organizationName}`,
    text: `Accept your invitation: ${webURL}/accept-invitation/${invitationId}`,
  };
}
