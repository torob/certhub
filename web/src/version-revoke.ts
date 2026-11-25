// Revoking a certificate version cannot be undone. The "Revoke" row action only
// opens a confirmation dialog. The revoke request is sent only when the user
// confirms in that dialog.

// Request body for POST /v1/certificates/{id}/versions/{version_id}/revoke.
export const versionRevokeBody = { reason: "cessation_of_operation" } as const;

export type VersionRevokeEvent<V> =
  // The "Revoke" row action of a version in the certificate version list.
  | { type: "request"; version: V }
  // The confirm button of the dialog.
  | { type: "confirm" }
  // Cancel, the close button, Escape, the backdrop, or the request finished.
  | { type: "close" };

export type VersionRevokeStep<V> = {
  // The version that the confirmation dialog shows. No dialog when undefined.
  confirming?: V;
  // Send the revoke request for this version.
  send?: V;
};

export function versionRevokeStep<V>(confirming: V | undefined, event: VersionRevokeEvent<V>): VersionRevokeStep<V> {
  switch (event.type) {
    case "request":
      return { confirming: event.version };
    case "confirm":
      // The dialog stays open and shows progress while the request runs.
      return confirming === undefined ? {} : { confirming, send: confirming };
    case "close":
      return {};
  }
}
