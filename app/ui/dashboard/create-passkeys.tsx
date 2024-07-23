"use client"

import { generateCredentialOptions, registerPasskeys } from "@/app/lib/actions";
import { Button } from "../button";
import base64url from "base64url";
import { AuthenticatorTransportFuture } from "@simplewebauthn/types";

export default function CreatePasskey() {
    // const {data: session} = useSession
    async function createPasskey() {
        const email = document.cookie
        .split("; ")
        .find((row) => row.startsWith("username="))
        ?.split("=")[1];
        if(email) {
            const opt = await generateCredentialOptions(email);
            const options: PublicKeyCredentialCreationOptions = {
                ...opt,
                user: {
                    ...opt.user,
                    id: Buffer.from(base64url.decode(opt.user.id))
                },
                challenge: Buffer.from(base64url.decode(opt.challenge)),
                excludeCredentials: opt.excludeCredentials?.map(v => ({...v, id: Buffer.from(v.id), transports: v.transports as AuthenticatorTransport[]}))
            }

            // Use platform authenticator and discoverable credential
            options.authenticatorSelection = {
                authenticatorAttachment: 'platform',
                requireResidentKey: true
            }
            const credentials = await navigator.credentials.create({
                publicKey: options as PublicKeyCredentialCreationOptions
            });
            credentials?.id && await registerPasskeys(email as string, credentials?.id, credentials.type as AuthenticatorTransportFuture);
        }
    }
    return <Button onClick={createPasskey} className="float-right text-blue-500 bg-white,da">Create Passkey</Button>
}