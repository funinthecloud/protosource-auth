import { ProtosourceClient, type AuthProvider } from "@protosource/client";
import { UserHTTPClient } from "./gen/auth/user/v1/user.protosource.client.js";
import { RoleHTTPClient } from "./gen/auth/role/v1/role.protosource.client.js";
import { IssuerHTTPClient } from "./gen/auth/issuer/v1/issuer.protosource.client.js";
import { KeyHTTPClient } from "./gen/auth/key/v1/key.protosource.client.js";
import { TokenHTTPClient } from "./gen/auth/token/v1/token.protosource.client.js";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

const cookieFetch: typeof fetch = (input, init) =>
  fetch(input, { ...init, credentials: "include" });

class CookieAuth implements AuthProvider {
  private actorId = "";

  setActor(actor: string) {
    this.actorId = actor;
  }

  actor(): string {
    return this.actorId;
  }

  authenticate(_headers: Headers): void {
    // No-op: identity flows via the shadow cookie that cookieFetch attaches.
  }
}

const auth = new CookieAuth();

export function setActor(actor: string) {
  auth.setActor(actor);
}

const client = new ProtosourceClient(API_BASE, auth, { useJSON: true, fetch: cookieFetch });

export const userClient = new UserHTTPClient(client);
export const roleClient = new RoleHTTPClient(client);
export const issuerClient = new IssuerHTTPClient(client);
export const keyClient = new KeyHTTPClient(client);
export const tokenClient = new TokenHTTPClient(client);
