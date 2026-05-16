import { ProtosourceClient, NoAuth } from "@protosource/client";
import { UserHTTPClient } from "./gen/auth/user/v1/user.protosource.client.js";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

const cookieFetch: typeof fetch = (input, init) =>
  fetch(input, { ...init, credentials: "include" });

const auth = new NoAuth("");

export function setActor(actor: string) {
  (auth as unknown as { _actor: string })._actor = actor;
}

const client = new ProtosourceClient(API_BASE, auth, { useJSON: true, fetch: cookieFetch });

export const userClient = new UserHTTPClient(client);
