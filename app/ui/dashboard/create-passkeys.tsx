"use client"

import { generateCredentialOptions, registerPasskeys } from "@/app/lib/actions";
import { Button } from "../button";
import base64url from "base64url";
import { AuthenticatorTransportFuture } from "@simplewebauthn/types";

export default function CreatePasskey() {
    async function createPasskey() {
        const email = document.cookie
        .split("; ")
        .find((row) => row.startsWith("username="))
        ?.split("=")[1];
        if(email) {
            const options = await generateCredentialOptions(email);
            options.user.id = base64url.decode(options.user.id);
            options.challenge = base64url.decode(options.challenge);
            if (options.excludeCredentials) {
                for (let cred of options.excludeCredentials) {
                cred.id = base64url.decode(cred.id);
                }
            }

            // Use platform authenticator and discoverable credential
            options.authenticatorSelection = {
                authenticatorAttachment: 'platform',
                requireResidentKey: true
            }
            const credentials = await navigator.credentials.create({

            });
            credentials?.id && await registerPasskeys(email as string, credentials?.id, credentials.type as AuthenticatorTransportFuture);
        }
    }
    return <Button onClick={createPasskey} className="float-right text-blue-500 bg-white,da">Create Passkey</Button>
}